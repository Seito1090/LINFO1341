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
    
def procecss_dns(file_path):
    possible_types = ['A', 'AAAA', 'CNAME', 'NS']
    dns_querry_names = []
    dns_types = [0 for _ in range(len(possible_types))]
    cap = ps.FileCapture(file_path)
    dns_requests = 0
    dns_responses = 0
    dns_unexpected = 0

    # Iterate over each packet in the capture file
    for pkt in cap:
        # Check if the packet contains a DNS layer
        if 'DNS' in pkt:
            dns_layer = pkt['DNS']
            flag = dns_layer.flags

            # Determine if the packet is a DNS request, response or unexpected case
            if flag == '0x0100':
                dns_requests += 1
                # Determine what the DNS query is about
                if dns_layer.qry_type == "1":
                    dns_types[0] += 1
                elif dns_layer.qry_type == "28":
                    dns_types[1] += 1
                elif dns_layer.qry_type == "5": 
                    dns_types[2] += 1
                elif dns_layer.qry_type == "2":
                    dns_types[3] += 1
            elif flag == '0x8180':
                dns_responses += 1
            else:
                dns_unexpected += 1
            
            dns_querry_names.append(dns_layer.qry_name) if dns_layer.qry_name not in dns_querry_names else None

    total = dns_requests + dns_responses + dns_unexpected

    # Plotting the data
    fig, ax = plt.subplots()
    ax.bar(['DNS Requests', 'DNS Responses', 'Unexpected cases', 'Total DNS querries'], [dns_requests, dns_responses, dns_unexpected, total])
    #Change color of the bars
    ax.patches[2].set_facecolor('red')
    ax.patches[1].set_facecolor('green')
    ax.patches[0].set_facecolor('green')
    ax.patches[3].set_facecolor('blue')
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Number of packets')
    ax.set_title('Number of DNS requests and responses')
    # Show the total number of DNS queries in the plot
    for i in range(4):
        ax.text(i, ax.patches[i].get_height(), str(ax.patches[i].get_height()), ha='center', va='bottom')
    plt.show()
    fig.savefig('graphs/web/dns_requests_responses.png')

    # Plotting the number of IPv4 and IPv6 DNS queries
    fig, ax = plt.subplots()
    # Plot the relevent data regarding the DNS queries, if the number of queries is 0, the bar will not be shown
    for a in range(len(possible_types)):
        if dns_types[a] > 0:
            ax.bar(possible_types[a], dns_types[a])
    #Change color of the bars, the bars that are in the dns_types list are colored in green
    for i in range(len(ax.patches)):
        ax.patches[i].set_facecolor('green')
    # Add the total number of DNS queries to the plot
    ax.bar('Total DNS queries', dns_requests)
    ax.patches[-1].set_facecolor('blue')
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Number of packets')
    ax.set_title('Different types of DNS queries')
    # Show the total number of DNS queries in the plot
    for i in range(len(ax.patches)):
        ax.text(i, ax.patches[i].get_height(), str(ax.patches[i].get_height()), ha='center', va='bottom')
    plt.show()
    fig.savefig('graphs/web/dns_queries.png')

    # Print the different percentages 
    print('Total DNS packets exchanged:', total)
    print('DNS requests:', dns_requests, '(', (dns_requests/total)*100, '%)')
    print('DNS responses:', dns_responses, '(', (dns_responses/total)*100, '%)')
    print('Unexpected cases:', dns_unexpected, '(', (dns_unexpected/total)*100, '%)')
    print('IPv4 DNS queries:', dns_types[0], '(', (dns_types[0]/dns_requests)*100, '%)')
    print('IPv6 DNS queries:', dns_types[1], '(', (dns_types[1]/dns_requests)*100, '%)')
    print('CNAME DNS queries:', dns_types[2], '(', (dns_types[2]/dns_requests)*100, '%)')
    print('NS DNS queries:', dns_types[3], '(', (dns_types[3]/dns_requests)*100, '%)')

    # Print the DNS query names
    print('Different DNS query names:')
    for i in range(len(dns_querry_names)):
        print(dns_querry_names[i])


if __name__ == '__main__':
    # Path is passed as an argument 
    procecss_dns('web_data/login_et_chargement_accueil.pcapng')
    '''if len(sys.argv) != 3:
        print('Usage: python process_data.py <type_of_processing> <path_to_pcapng_file>')
        sys.exit(1)
    type_processing = sys.argv[1]
    file_path = sys.argv[2]
    if type_processing == 'dns':
        procecss_dns(file_path)
    elif type_processing == 'data':
        process_data(file_path)'''