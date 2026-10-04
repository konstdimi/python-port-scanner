import socket
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
import argparse
import json
import csv
from datetime import datetime #just for storing the date of each scan

def getB(s: socket.socket):
    #attempting to grab the banner
    try:
        #sending a typical head request
        s.send(b"HEAD / HTTP/1.1\r\n\r\n")

        rcvd_banner = s.recv(1024).decode('utf-8', errors= 'ignore').strip()
        return rcvd_banner.split('\n')[0] if rcvd_banner else "No banner"
    
    except Exception:
            return "No banner"


def check(ip: str, port: int, socket_t_out: float = 1.0, grab_banner: bool = False):
    #checking if the specific port on the given ip is open
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(socket_t_out)
        is_open = s.connect_ex((ip, port))
        banner = ""

        
        if is_open == 0:
            if grab_banner:
                banner = getB(s)
            s.close()
            return (port, True, banner)

        s.close()
        return (port, False, "")

    except (socket.error, socket.timeout):
        return (port, False, "")



def save(filename: str, target_domain: str, open_ports: list, scanning_time: float):
    """creating a file named by the user and storing the scannning results there.
        while deducting the format from filename's ending (must be .json or .csv)"""
    if "." in filename:
        file_format = filename.split(".")[1].lower()
        if file_format == "json":
                 data = {"scan_results": { "target" : target_domain,
                                            "datetime_of_scan" : datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
                                            "scanning_duration_seconds" : round(scanning_time, 2),
                                            "total_open_ports" : len(open_ports)},
                      "open_ports" : [{"port" : port, "banner" : banner}
                           for port, banner in open_ports ]     }
       
                 try:
                      file = open(filename, "w", encoding= "utf-8")
                      json.dump(data, file)
                      print(f"Scanning results were stored in file: {filename}")
                 finally:
                      file.close()
        
        elif file_format == "csv":
                with open(filename, "w", newline= "", encoding= "utf-8") as file:
                      writer = csv.writer(file) 
                      writer.writerow(["Port", "Status", "Banner"])
                      for port, banner in open_ports:
                            writer.writerow([port, "OPEN", banner])
                      print(f"Scanning results were stored in file: {filename}")

        else:
             print(f"Invalid filename! | Must be a '.json' or '.csv' type file and have no other '.'")

    else:
         print(f"Invalid filename! | Must be a '.json' or '.csv' type file")                    
                      



def main():
    #we want the user parsing all nessesary info from the command line
    cl_listen = argparse.ArgumentParser(description= "Python port scanner")
    cl_listen.add_argument("-d", "--domain", required= True, help= "Ip or domain target")
    cl_listen.add_argument("-p", "--ports", default= "1-1024", help= "Port range")
    cl_listen.add_argument("-t", "--threads", type= int, default= 100, help= "Max number of threads")
    cl_listen.add_argument("-b", "--banner", action= "store_true", help= "Enable Banner Grabber")
    cl_listen.add_argument("--timeout", type= float, default= 1.0, help= "Socket timeout seconds (default: 1.0)")
    cl_listen.add_argument("-o", "--output", help= "Filename to save results (e.g. outputs_file.json)")

    cl_info = cl_listen.parse_args()

   #resolving given domain:
    try:
        ip = socket.gethostbyname(cl_info.domain)
    except socket.gaierror:
        print(f"Couldn't resolve domain: {cl_info.domain}")
        sys.exit(1)

    #turning given 'start-end' string into start and end integers
    try:
            if '-' in cl_info.ports:
                start, end = map(int, cl_info.ports.split('-'))
                
            else:
                #if they give just a number (eg 80)
                start = end = int(cl_info.ports)
    
    except ValueError:
                print(f"Error: port range should be given as '1-100' or '25'")
                sys.exit(1)

    
    open_ports = [] 
    start_t = time.time()

    with ThreadPoolExecutor(max_workers= cl_info.threads) as thread:
        tasks = [thread.submit(check, ip, port, cl_info.timeout, cl_info.banner)
        for port in range(start, end + 1)]

        try:
            for task in as_completed(tasks):
                (port, is_open, banner) = task.result()
                if is_open:
                    open_ports.append((port, banner))
                    if cl_info.banner and banner:
                         print(f"Port: {port} is Open | Banner: {banner}")
                    else:
                        print(f"Port: {port} is Open")

        #cancel all next tasks in case of user interruption
        except KeyboardInterrupt:
            print(f"Scanning was interrupted by the user (pressed Ctrl + C)")
            thread.shutdown(wait= False, cancel_futures= True)
            sys.exit(0)


        end_t = time.time()


        """the ports stored in open_ports list are in a chaotic order.
            sorting it based on port number"""
        open_ports.sort(key= lambda x: x[0])
        
        print(f"Scanning was finished in {end_t - start_t} sec")
        print(f"{len(open_ports)} ports found open.")
        
        if cl_info.output:
            save(cl_info.output, cl_info.domain, open_ports, end_t - start_t)

       


main()