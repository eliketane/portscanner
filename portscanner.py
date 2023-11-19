import optparse
from socket import *
from threading import *

screenLock = Semaphore(value=1)

def connScan(tgtHost, tgtPort):
    try:
        connSkt = socket(AF_INET, SOCK_STREAM)
        connSkt.connect((tgtHost, tgtPort))
        connSkt.send(b'stonecold\r\n')
        results = connSkt.recv(100)
        screenLock.acquire()
        print('[+] %d/tcp open' % tgtPort)
        if not results:  # Check if results is empty
            print('[+] No data received')
        else:
            print('[+] ' + str(results))
    except Exception as e:
        screenLock.acquire()
        print('[-] %d/tcp closed: %s' % (tgtPort, str(e)))
    finally:
        screenLock.release()
        connSkt.close()


def portScan(tgtHost, tgtPorts):
    try:
        tgtIP = gethostbyname(tgtHost)
    except:
        print("[-] Cannot resolve '%s': Unknown host" % tgtHost)
        return

    try:
        tgtName = gethostbyaddr(tgtIP)
        print('\n[+] Scan Results for: ' + tgtName[0])
    except:
        print('\n[+] Scan Results for: ' + tgtIP)

    setdefaulttimeout(1)
    for tgtPort in tgtPorts:
        t = Thread(target=connScan, args=(tgtHost, int(tgtPort)))
        t.start()

def main():
    parser = optparse.OptionParser('usage%prog ' + '-H <target host> -p <target port>')
    parser.add_option('-H', dest='tgtHost', type='string', help='specify target host')
    parser.add_option('-p', dest='tgtPort', type='string', help='specify target port[s] separated by comma')
    (options, args) = parser.parse_args()
    tgtHost = options.tgtHost
    tgtPorts = [port.strip() for port in str(options.tgtPort).split(',') if port.strip()]  # Filter out empty strings

    if (tgtHost is None) or (not tgtPorts):
        print(parser.usage)
        exit(0)

    portScan(tgtHost, tgtPorts)


if __name__ == "__main__":
    main()
