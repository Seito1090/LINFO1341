import pyshark as ps 
import matplotlib.pyplot as plt
import numpy as np
import os

def get_dns_stats(file_path):
    okips = ['20.42.73.28',
             '20.199.120.182',
             '20.135.20.1',
             '20.223.35.26',
             '2001:6a8:3081:6f21:dd2e:440a:becc:68ff']
    dns_requests = 0
    dns_responses = 0
    dns_unexpected = 0
    
    dns_ttl = 0
    
    cap = ps.FileCapture(file_path)

    # Iterate over each packet in the capture file
    for pkt in cap:
        # Check if the packet contains a DNS layer
        if ('IP' in pkt or 'IPV6 in pkt') and 'DNS' in pkt:
            if pkt['IP' if 'IP' in pkt else 'IPV6'].src in okips or pkt['IP' if 'IP' in pkt else 'IPV6'].dst in okips:
                dns_layer = pkt['DNS']
                flag = dns_layer.flags

                # Determine if the packet is a DNS request, response or unexpected case
                if flag == '0x0100':
                    dns_requests += 1
                elif flag == '0x8180':
                    dns_responses += 1
                    # Determine the time to live of the DNS response
                    dns_ttl += int(dns_layer.resp_ttl)
                else:
                    dns_unexpected += 1

    total = dns_requests + dns_responses + dns_unexpected
    cap.close()

    return [total, dns_requests, dns_responses, dns_unexpected, dns_ttl]

def get_types(file_path):
    okips = ['20.42.73.28',
             '20.199.120.182',
             '20.135.20.1',
             '20.223.35.26',
             '13.107.42.12',
             '2001:6a8:3081:6f21:dd2e:440a:becc:68ff']
    possible_types = ['A', 'AAAA', 'CNAME', 'NS', 'HTTPS']
    dns_types = np.zeros(len(possible_types))
    cap = ps.FileCapture(file_path)
    for pkt in cap:
        if ('IP' in pkt or 'IPV6 in pkt') and 'DNS' in pkt:
            if pkt['IP' if 'IP' in pkt else 'IPV6'].src in okips or pkt['IP' if 'IP' in pkt else 'IPV6'].dst in okips:
                dns_layer = pkt['DNS']
                if dns_layer.flags == '0x0100':
                    if dns_layer.qry_type == "1":
                        dns_types[0] += 1
                    elif dns_layer.qry_type == "28":
                        dns_types[1] += 1
                    elif dns_layer.qry_type == "5": 
                        dns_types[2] += 1
                    elif dns_layer.qry_type == "2":
                        dns_types[3] += 1
                    elif dns_layer.qry_type == "65":
                        dns_types[4] += 1
    cap.close()
    return dns_types

def show_dns_tot_stats(stats, type_infos):

    possible_types = ['A', 'AAAA', 'CNAME', 'NS', 'HTTPS']
    # Plotting the data
    fig, ax = plt.subplots()
    ax.bar(['Total DNS packets', 'DNS Requests', 'DNS Responses', 'Unexpected'], stats[:4])
    #Change color of the bars
    ax.patches[3].set_facecolor('red')
    ax.patches[2].set_facecolor('green')
    ax.patches[1].set_facecolor('green')
    ax.patches[0].set_facecolor('blue')
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Number of packets')
    ax.set_title('Number of DNS requests and responses')
    # Show the total number of DNS queries in the plot
    for i in range(4):
        ax.text(i, ax.patches[i].get_height(), str(ax.patches[i].get_height()), ha='center', va='bottom')
    # show the average time to live of the DNS responses as a text
    plt.show()
    name0 = 'graphs/' + 'app' + '/dns_requests_responses' + '.png'
    fig.savefig(name0)

    # Plotting the number of IPv4 and IPv6 DNS queries
    fig, ax = plt.subplots()
    # Plot the relevent data regarding the DNS queries, if the number of queries is 0, the bar will not be shown
    ax.bar('Total DNS queries', stats[1])
    ax.patches[0].set_facecolor('blue')
    for a in range(len(possible_types)):
        if type_infos[a] > 0:
            ax.bar(possible_types[a], type_infos[a])
    #Change color of the bars, the bars that are in the dns_types list are colored in green
    for i in range(1, len(ax.patches)):
        ax.patches[i].set_facecolor('green')
    # Add the total number of DNS queries to the plot
    
    ax.set_xlabel('Protocol')
    ax.set_ylabel('Number of packets')
    ax.set_title('Different types of DNS queries')
    # Show the total number of DNS queries in the plot
    for i in range(len(ax.patches)):
        ax.text(i, ax.patches[i].get_height(), str(ax.patches[i].get_height()), ha='center', va='bottom')
    plt.show()
    name1 = 'graphs/' + 'app' + '/dns_queries' + '.png'
    fig.savefig(name1)

def process_dns(file_path, seq_nbr):
    case_study = None
    if "web" in file_path:
        case_study = 0
    else :
        case_study = 1

    dns_requests = 0
    dns_responses = 0
    dns_unexpected = 0
    
    possible_types = ['A', 'AAAA', 'CNAME', 'NS']
    dns_querry_names = []
    dns_types = np.zeros(len(possible_types))
    dns_ttl = 0
    
    cap = ps.FileCapture(file_path)

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
                # Determine the time to live of the DNS response
                dns_ttl += int(dns_layer.resp_ttl)
            else:
                dns_unexpected += 1

            dns_querry_names.append(dns_layer.qry_name) if dns_layer.qry_name not in dns_querry_names else None

    total = dns_requests + dns_responses + dns_unexpected
    dns_ttl = dns_ttl/dns_responses

    # Plotting the data
    fig, ax = plt.subplots()
    ax.bar(['DNS Requests', 'DNS Responses', 'Unexpected', 'Total DNS querries'], [dns_requests, dns_responses, dns_unexpected, total])
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
    name0 = 'graphs/' + ('web' if case_study == 0 else 'app') + '/dns_requests_responses' + str(seq_nbr) +'.png'
    fig.savefig(name0)

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
    name1 = 'graphs/' + ('web' if case_study == 0 else 'app') + '/dns_queries' + str(seq_nbr) +'.png'
    fig.savefig(name1)

    # Print the different percentages 
    print('Average time to live:', dns_ttl)
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
    cap.close()

def process_network(file_path, seq_nbr):
    returned_ipsv4 = []
    returned_ipsv6 = []
    names_ipv4 = []
    names_ipv6 = []

    cap = ps.FileCapture(file_path)

    stop = 10
    
    print("yello")
    for pkt in cap:
        print(pkt)
        if 'IP' in cap and stop > 0:
            if pkt['IP'].version == '4':
                names_ipv4.append(pkt['IP'].src)
            else:
                names_ipv6.append(pkt['IP'].src)
        stop -= 1
        if stop == 0:
            break
    print(len(names_ipv4))
    print(len(names_ipv6))   
    cap.close()


if __name__ == '__main__':
    # Path is passed as an argument 
    stats = [0,0,0,0,0] # total dns packets, dns requests, dns responses, unexpected cases, dns ttl
    type_infos = [0,0,0,0,0] # A, AAAA, CNAME, NS, HTTPS
    #get dir 
    dirpath = 'app_data/Wifi UCL'
    #get all files .pcapng in the dir
    files = [dirpath + "/" + f for f in os.listdir(dirpath) if os.path.isfile(os.path.join(dirpath, f)) and f.endswith('.pcapng')]    
    print(files)
    for file in files :
        infos = get_dns_stats(file)
        dns_types = get_types(file)
        stats = [stats[i] + infos[i] for i in range(len(stats))]
        type_infos = [type_infos[i] + dns_types[i] for i in range(len(type_infos))]
    stats[-1] = stats[-1]/stats[2] if stats[2] > 0 else stats[-1]
    print(stats)
    print(type_infos)
    show_dns_tot_stats(stats, type_infos)
    #process_dns('web_data/logout.pcapng', 10)
    '''if len(sys.argv) != 3:
        print('Usage: python process_data.py <type_of_processing> <path_to_pcapng_file> <seq>')
        sys.exit(1)
    type_processing = sys.argv[1]
    file_path = sys.argv[2]
    seq_nbr = sys.argv[3]
    if type_processing == 'dns':
        procecss_dns(file_path, seq_nbr)
    elif type_processing == 'data':
        process_data(file_path)'''