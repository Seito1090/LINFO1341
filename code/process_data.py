import pyshark as ps 
import matplotlib.pyplot as plt

def process_data(file_path):
    cap = ps.FileCapture(file_path)
    nbr_ipv4 = 0
    tot = 0
    # count the number of ipv4 and ipv6 packets in the pcapng file, in the file this information is stored like this : Layer IP:       0100 .... = Version: 4
    for pkt in cap:
        tot += 1
        if 'IP' in pkt:
            if pkt['IP'].version == '4':
                nbr_ipv4 += 1

    nbr_ipv6 = tot - nbr_ipv4

    # Plotting the data
    fig, ax = plt.subplots()
    ax.bar(['IPv4', 'IPv6', 'Total'], [nbr_ipv4, nbr_ipv6, tot])
    #Change color of the bars
    ax.patches[0].set_facecolor('red')
    ax.patches[1].set_facecolor('blue')
    ax.patches[2].set_facecolor('green')
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Number of packets')
    ax.set_title('Number of IPv4 and IPv6 packets')
    plt.show()

    print('Number of IPv4 packets:', nbr_ipv4)
    print('Number of IPv6 packets:', nbr_ipv6)
    print('Total number of packets:', tot)
    

if __name__ == '__main__':
    # Path is passed as an argument 
    process_data('web_data/take4.pcapng')
    '''if len(sys.argv) != 2:
        print('Usage: python process_data.py <path_to_pcapng_file>')
        sys.exit(1)
    file_path = sys.argv[1]
    process_data(file_path)'''