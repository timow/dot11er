dot11er
=======

dot11er implements a framework and some tools for playing with IEEE 802.11. The
main idea behind is to handle 802.11 frames in an event-driven manner relying on
[redis](http://redis.io/).

                                +------------------+
                                |  redis instance  |
                                |                  |
    +------------+   rx frames  |   +----------+   |
    |            |--------------+-->| rx_frame |   |
    |            |              |   |  queue   |   |
    |            |              |   +----------+   |
    |  WLAN NIC  |              |                  |
    |            |              |   +----------+   |
    |            |<-------------+---| tx_frame |   |
    |            |   tx frames  |   |  queue   |   |
    +------------+              |   +----------+   |
                                |                  |
                                +------------------+

Requirements
------------

* Hardware:
  Some WLAN card being capable of frame injection (e.g. ALFA AWUS036H).

* Software:

    * [redis server](http://redis.io/), tested with version 2.8.17

    * [libpcap](http://www.tcpdump.org/), tested with version 1.3.0

    * [redis-py](http://github.com/andymccurdy/redis-py/), tested with version 2.4.13

    * [hiredis](https://github.com/redis/hiredis), tested with version 0.10.1

    * Scapy with addtional 802.11 patches, currently available [here](https://bitbucket.org/timo_warns/scapy)
