import netaddr

from rally.common import log as logging
from rally.common import sshutils
from rally import consts
from rally.plugins.openstack import scenario
from rally.plugins.openstack.scenarios.vm import utils as vmutils
from rally import exceptions
from rally.task import types
from rally.task import atomic
from rally.task import utils
from rally.task import validation


LOG = logging.getLogger(__name__)


class VRRPScenario(vmutils.VMScenario):
    """Benchmark scenarios for Neutron l3-ha."""

    def get_master_agent(self, router_id):
        net_admin = self._admin_clients.neutron()

        def get_actives(r):
            agents = net_admin.list_l3_agent_hosting_routers(r)
            active_agents = filter(
                lambda d: d.get("ha_state") == "active",
                agents.get("agents", []))
            LOG.info("Router %s is ACTIVE on: %s" % (r, [(a["id"], a["host"])
                                                         for a in
                                                         active_agents]))
            return active_agents

        utils.wait_is_ready(
            router_id,
            is_ready=utils.resource_is(str(1),
                                       lambda x: str(len(get_actives(x)))),
            timeout=vmutils.CONF.benchmark.vm_ping_timeout,
            check_interval=vmutils.CONF.benchmark.vm_ping_poll_interval

        )
        masters = get_actives(router_id)
        LOG.info("Found router %s master on agent %s" % (router_id,
                                                         (masters[0]["id"],
                                                          masters[0]["host"])))
        return masters[0]

    def failover(self, host, command):
        """

        :param host:
        :param command:
        :return:
        """
        LOG.info("Host: %s. Injecting Failover %s" % (host["address"],
                                                      command))
        code, out, err = self._run_command(
            server_ip=host.get("address"),
            port=host.get("port", 22),
            username=host.get("username"),
            password=host.get("password"),
            key_filename=host.get("key_filename"),
            pkey=host.get("pkey"),
            command=command
        )
        if code and code > 0:
            raise exceptions.ScriptError(
                "Error running command %(command)s. "
                "Error %(code)s: %(error)s" % {
                    "command": command, "code": code, "error": err})

    def get_router(self, server, fip):
        """Retrieves server's GW router

        :param server: nova.servers obj
        :param fip: server's floating IP
        :return: uuid of server's GW router
        """

        nets = [name for name, addresses
                in server.networks.iteritems()
                if fip["ip"] in addresses]
        assert len(nets) == 1, "Found too many networks: %s" % nets
        LOG.debug("Server's network: %s" % nets[0])

        routers = [n.get("router_id") for n in
                   self.context.get("tenant", {}).get("networks", [])
                   if n["name"] == nets[0]]
        assert len(routers) == 1, "Found too many routers: %s" % routers
        LOG.debug("Server's router: %s" % routers[0])

        return routers[0]

    def _wait_for_ping(self, server_ip):
        """Ping the server repeatedly.

        Note: Shadows vm._wait_for_ping to allow dynamic names for atomic
            actions.

        :param server_ip: address of the server to ping
        :param duration: duration of the loop in seconds
        :param interval: time between iterations
        """

        server_ip = netaddr.IPAddress(server_ip)
        utils.wait_for(
            server_ip,
            is_ready=utils.resource_is(vmutils.ICMP_UP_STATUS,
                                       self._ping_ip_address),
            timeout=vmutils.CONF.benchmark.vm_ping_timeout,
            check_interval=vmutils.CONF.benchmark.vm_ping_poll_interval
        )


        # duration = duration or vmutils.CONF.benchmark.vm_ping_timeout,
        # interval = interval or vmutils.CONF.benchmark.vm_ping_poll_interval
        # server_ip = netaddr.IPAddress(server_ip)
        #
        # utils.wait_for(
        #     server_ip,
        #     is_ready=utils.resource_is(vmutils.ICMP_UP_STATUS,
        #                                self._ping_ip_address),
        #     timeout=duration,
        #     check_interval=interval
        # )

    def _run_command(self, server_ip, port, username, password, command,
                     pkey=None, key_filename=None):
        """Run command via SSH on server.

        Create SSH connection for server, wait for server to become available
        (there is a delay between server being set to ACTIVE and sshd being
        available). Then call run_command_over_ssh to actually execute the
        command.

        Note: Shadows vm.utils.VMScenario._run_command to support key_filename.

        :param server_ip: server ip address
        :param port: ssh port for SSH connection
        :param username: str. ssh username for server
        :param password: Password for SSH authentication
        :param command: Dictionary specifying command to execute.
            See `rally info find VMTasks.boot_runcommand_delete' parameter
            `command' docstring for explanation.
        :param key_filename: private key filename for SSH authentication
        :param pkey: key for SSH authentication

        :returns: tuple (exit_status, stdout, stderr)
        """
        if not key_filename:
            pkey = pkey or self.context["user"]["keypair"]["private"]
        ssh = sshutils.SSH(username, server_ip, port=port,
                           pkey=pkey, password=password,
                           key_filename=key_filename)
        self._wait_for_ssh(ssh)
        return self._run_command_over_ssh(ssh, command)

    @types.set(image=types.ImageResourceType,
               flavor=types.FlavorResourceType)
    @validation.image_valid_on_flavor("flavor", "image")
    @validation.valid_command("command", required=False)
    @validation.external_network_exists("floating_network")
    @validation.required_services(consts.Service.NOVA, consts.Service.NEUTRON)
    @validation.required_openstack(users=True)
    @scenario.configure(context={"cleanup": ["nova", "neutron"],
                                 "keypair": {}, "allow_ssh": {}})
    def boot_failover_poll(self, image, flavor,
                           floating_network=None,
                           use_floating_ip=True,
                           # force_delete=False,
                           poll_duration=0,
                           poll_interval=0,
                           l3_nodes=None,
                           command=None,
                           **kwargs):
        """Boot a server with l3-ha router. Verify connectivity after failover

        :param poll_duration: int. 0 will use defaults from conf
        :param poll_interval: int. 0 will use defaults from conf
        :param l3_nodes: dictionary with credentials to the different l3-nodes
            where the keys are the agent host-names from the Neutron DB

            Examples::

                l3_nodes: {
                  net1: {
                    address: 10.35.186.187
                    username: root
                    password: 123456,
                    port: 21
                  },
                  net2: {
                    address: net2.example.com
                    username: root
                    pkey: /path/to/ssh/id_rsa.pub
                  }
                }
        :param command: dict. Command that will be used to trigger failover
            will be executed via ssh on the node hosting the l3-agent. For more
            details see: VMTask.boot_runcommand_delete.command

        Note: failure injection usually requires root acess to the nodes,
            eithre via root user or by disabling 'Defaults requiretty' in
            /etc/sudoers
        """
        server, fip = self._boot_server_with_fip(
            image, flavor, use_floating_ip=use_floating_ip,
            floating_network=floating_network,
            key_name=self.context["user"]["keypair"]["name"],
            **kwargs)

        router_id = self.get_router(server, fip)

        with atomic.ActionTimer(self, "VRRP.get_master_agent.init"):
            master = self.get_master_agent(router_id)

        with atomic.ActionTimer(self, "VRRP.wait_for_ping.init_server"):
            self._wait_for_ping(fip["ip"])

        self.failover(host=l3_nodes[master["host"]],
                      command=command)
        with atomic.ActionTimer(self, "VRRP.wait_for_ping.after_failover"):
            self._wait_for_ping(fip["ip"])
        with atomic.ActionTimer(self, "VRRP.get_master_agent.after_failover"):
            master_new = self.get_master_agent(router_id)

        msg = "router remains ACTIVE on the same node"
        assert master_new["id"] != master["id"], msg