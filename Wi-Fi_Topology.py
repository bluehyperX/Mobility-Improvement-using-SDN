#!/usr/bin/python

from mininet.node import RemoteController, OVSKernelSwitch, Host
from mininet.log import setLogLevel, info
from mn_wifi.net import Mininet_wifi
from mn_wifi.node import Station, OVSKernelAP
from mn_wifi.cli import CLI
from mn_wifi.link import wmediumd
from mn_wifi.wmediumdConnector import interference
from subprocess import call

def myNetwork():

    net = Mininet_wifi(controller=RemoteController,
                       link=wmediumd,
                       wmediumd_mode=interference,
                    #    ipBase='10.0.0.0/8'
                    )

    info( '*** Adding controller\n' )
    c0 = net.addController(name='c0', controller=RemoteController, port=6653)

    info( '*** Adding switches/APs\n')
    s1 = net.addSwitch('s1', cls=OVSKernelSwitch)
    s2 = net.addSwitch('s2', cls=OVSKernelSwitch)
    s3 = net.addSwitch('s3', cls=OVSKernelSwitch)
    s4 = net.addSwitch('s4', cls=OVSKernelSwitch)
    s5 = net.addSwitch('s5', cls=OVSKernelSwitch)
    ap1 = net.addAccessPoint('ap1', cls=OVSKernelAP, ssid='ap1-ssid', channel='1', mode='g', position='300.0,400.0,0', range=200)
    ap2 = net.addAccessPoint('ap2', cls=OVSKernelAP, ssid='ap2-ssid', channel='6', mode='g', position='1500.0,400.0,0', range=200)
    ap3 = net.addAccessPoint('ap3', cls=OVSKernelAP, ssid='ap3-ssid', channel='11', mode='g', position='2700.0,400.0,0', range=200)

    info( '*** Adding hosts/stations\n')
    h1 = net.addHost('h1', cls=Host, ip='10.0.0.1', defaultRoute=None)
    h2 = net.addHost('h2', cls=Host, ip='10.0.0.2', defaultRoute=None)
    h3 = net.addHost('h3', cls=Host, ip='10.0.0.3', defaultRoute=None)
    sta1 = net.addStation('sta1', ip='10.0.0.4', position='369.0,392.0,0', range=150)

    info("*** Configuring Propagation Model\n")
    net.setPropagationModel(model="logDistance", exp=4)

    info("*** Configuring wifi nodes\n")
    net.configureWifiNodes()

    info( '*** Adding links\n')
    net.addLink(s3, s5)
    net.addLink(s3, s4)
    net.addLink(s3, s2)
    net.addLink(s2, s1)
    net.addLink(s1, h1)
    net.addLink(s1, h2)
    net.addLink(s2, h3)
    net.addLink(ap1, s4)
    net.addLink(ap2, s3)
    net.addLink(ap3, s5)

    info( '*** Plotting graph\n')
    net.plotGraph(max_x=4000, max_y=4000)

    # info( '*** Starting controllers\n')
    # for controller in net.controllers:
    #     controller.start()

    info( '*** Starting network, controller and switches/APs\n')
    net.build()
    c0.start()
    net.get('s1').start([c0])
    net.get('s2').start([c0])
    net.get('s3').start([c0])
    net.get('s4').start([c0])
    net.get('s5').start([c0])
    net.get('ap1').start([c0])
    net.get('ap2').start([c0])
    net.get('ap3').start([c0])

    info( '*** Starting monitor interface and wireshark\n')
    sta1.cmd('iw dev %s interface add mon0 type monitor' % sta1.params['wlan'][0])
    sta1.cmd('ifconfig mon0 up')
    sta1.cmd('wireshark -i mon0 &')

    info( '*** Starting mobility\n')
    net.startMobility(time=0, repetitions=1, ac_method='ssf')
    net.mobility(sta1, 'start', time=10, position='300.0,450.0,0.0')
    net.mobility(sta1, 'stop', time=50, position='2700.0,450.0,0.0')
    net.stopMobility(time=51)

    info( '*** Running CLI\n')
    CLI(net)
    net.stop()


if __name__ == '__main__':
    setLogLevel( 'info' )
    myNetwork()

