#!/usr/bin/env python
# released at BSides Canberra by @infosec_au and @nnwakelam
# rewritten by happy3n1gma
# gotta <3 silvio

import argparse, time, requests, itertools, threading, time, datetime, tldextract, logging, re, os, dns.resolver
from threading import Lock
from functools import partial
from Queue import *
from tldextract.tldextract import LOG
from termcolor import colored


logging.basicConfig(level=logging.CRITICAL)

def parseArgs():
    parser = argparse.ArgumentParser()
    parser.add_argument("-i", "--input",
                        help="List of subdomains input", 
                        required=True)
    parser.add_argument("-o", "--output",
                        help="Output location for altered subdomains",
                        required=True)
    parser.add_argument("-b", "--bruteforce",
                        help="Bruteforce using no permutations - Wordlist Only",
                        required=False, action="store_true")
    parser.add_argument("-w", "--wordlist",
                        help="List of words to alter the subdomains with",
                        required=False, default="words.txt")
    parser.add_argument("-r", "--resolve",
                        help="Resolve all altered subdomains",
                        action="store_true")
    parser.add_argument("-n", "--add-number-suffix",
                        help="Add number suffix to every domain (0-9)",
                        action="store_true")
    parser.add_argument("-d", "--dnsservers",
                        help="IP addresses of resolver(s) to use separated by `,`. (overrides system default)", required=False)
    parser.add_argument("-sd", "--scanDomains",
                        help="Scan Domains: Using discovered subdomains restart scan process", 
                        default=False, action="store_true")
    parser.add_argument("-ds", "--depthSearch",
                        help="Depth Search: Search n levels beyond domain - ie: *.*..com (Warning - Slow!)", 
                        default=1, required=False, type=int)
    parser.add_argument("-s","--save",
                        help="File to save resolved altered subdomains to",
                        required=False)
    parser.add_argument("-t", "--threads",
                        help="Amount of threads to run simultaneously (Min Default 10)",
                        required=False, default=10, type=int)

    args = parser.parse_args()
    if args.resolve:
        try:
            args.resolve = open(args.save, "a")
        except:
            print("Please provide a file name to save results to "
                  "via the -s argument")
            raise SystemExit

    if args.threads < 10:
        print("{}".format(colored("Minimum Threads: 10","red")))
        args.threads = 10

    return args



class hunter(threading.Thread):
    def __init__(self, threadID, name, permDNS, domain_list):
        threading.Thread.__init__(self)
        self.threadID = threadID
        self.kill = False
        self.name = name
        self.parent = permDNS
        self.domain_pool = domain_list
        self.results = []

    def run(self):
        scan_domains(self)
        for result in self.results:
            self.parent.update_results(result)


    def update_results(self,update):
        ''' Store unique domains '''
        # not stored in previous cycle, nor current cycle
        if update not in self.parent.total_results and update not in self.results:
            self.results.append(update)
            if len(update) > 2 and update[2]:
                print("{} : {} : {}".format(colored(str(update[0]).strip(),"red"),colored(str(update[1]).strip(),"green"),colored(str(update[2]).strip(),"blue")))
            else:
                print("{} : {}".format(colored(str(update[0]).strip(),"red"),colored(str(update[1]).strip(),"green")))



class permDNS(object):
    def __init__(self,args):
        self.lock = Lock()
        self.args = args
        self.domain_pool = []
        self.domain_cnt = 0 

        self.total_results = []
        self.stage_results = []

        self.start = None
        self.stage_start = None
        self.stage_progress = 0

        # store wordlist and domainlist
        with open(self.args.wordlist, "r") as fp:
            self.wordlist = [line.replace('/', '').replace('\n','') for line in fp]
        if '' in self.wordlist:
            self.wordlist.remove('')

        with open(self.args.input, "r") as fp:
            self.domainlist = [line.replace('/', '').replace('\n','') for line in fp]

        if '' in self.domainlist:
            self.domainlist.remove('')

    def update_results(self,update):
        ''' Store new domains found '''
        self.lock.acquire()
        if update not in self.total_results:
            self.stage_results.append(update)
        self.lock.release()   


    def update_stage_progress(self):
        ''' Update stage_progress counter '''
        self.lock.acquire()
        self.stage_progress += 1
        self.print_progress()
        self.lock.release()


    def print_progress(self):
        ''' Print out stage progress '''
        if self.stage_progress % 500 == 0:
            left = self.domain_cnt-self.stage_progress
            secondspassed = (int(time.time())-self.stage_start)+1
            amountpersecond = self.stage_progress / secondspassed
            seconds = 0 if amountpersecond == 0 else int(left/amountpersecond)
            timeleft = str(datetime.timedelta(seconds=seconds))
            print(colored("[*] {0}/{1} completed, approx {2} left".format(self.stage_progress, self.domain_cnt, timeleft),"blue"))


    def add_domain(self,domain):
        ''' Add domain to pool '''
        self.domain_pool.append(domain)
        self.domain_cnt += 1


    def buildSubdomains(self):
        ''' Build pool of subdomains '''
        self.insert_all_indexes()

        if self.args.bruteforce is False:
            # if depth search, then extend all domains by depth
            if self.args.depthSearch > 1:
                self.extend_subdomains()

            self.insert_dash_subdomains()  
            self.join_words_subdomains()

            # add to our new list of domains that every newly created domain has number prefix/suffix
            if self.args.add_number_suffix is True:
                self.insert_number_suffix_subdomains()

        # if we should remove existing, save the output to a temporary file
        if self.args.ignore_existing is True:
            self.args.output_tmp = self.args.output + '.tmp'
        else:
            self.args.output_tmp = self.args.output

        # write to file
        with open(self.args.output_tmp, 'w') as fp:
            fp.writelines(self.domain_pool)



    def extend_subdomains(self):
        ''' 
            Extend each subdomain by depth using only wordlist (no permutations)

            Depth = 2
            Wordlist = {a,b}
            Original URL:  example.2019
            Modified URLS: a.b.example.com, b.a.example.com
        '''

        for sub in self.domainlist: 
            ext = tldextract.extract(sub.strip())
            current_sub = ext.subdomain.split(".")
            if '' in current_sub:
                current_sub.remove('')

            sublist = [list(current_sub)]
            for i in range(self.args.depthSearch):
                tmp = []
                for new_sub in sublist:
                    for word in self.wordlist:
                        s = list(new_sub)
                        s.insert(0, word)

                        if i == self.args.depthSearch - 1:
                            actual_sub = ".".join(s)
                            self.add_domain("{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix))
                        else:
                            tmp.append(s)
                    sublist = tmp


    def insert_all_indexes(self):
        ''' 
            Insert every word at every index of the subdomain and write new url to file
            
            Original URL:  example.2019 
            Modified URLS: new.example.2019 | example.new.2019 | example.2019.new
        '''
        for sub in self.domainlist: 
            ext = tldextract.extract(sub.strip())
            current_sub = ext.subdomain.split(".")

            if '' in current_sub:
                current_sub.remove('')

            for word in self.wordlist:
                for index in range(len(current_sub)+1):
                    current_sub.insert(index, word)
                    actual_sub = ".".join(current_sub)
                    self.add_domain("{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix))
                    current_sub.pop(index)


    def insert_number_suffix_subdomains(self):
        ''' 
            Insert number before and after every word 
            
            Original: example.2019.domain.com (adding number 9 to 2019)
            word-NUM: example.2019-9.domain.com
            NUM-word: example.9-2019.domain.com
            wordNUM:  example.20199.domain.com
            NUMword:  example.92019.domain.com
            wordZNUM: example.092019.domain.com
            ZNUM:word example.201909.domain.com

        '''
        for line in self.domainlist:
            ext = tldextract.extract(line.strip())
            current_sub = ext.subdomain.split(".")
            if '' in current_sub:
                current_sub.remove('')

            for num in range(10):
                for index in range(len(current_sub)):
                    #add word-NUM
                    original_sub = current_sub[index]
                    current_sub[index] = "{}-{}".format(current_sub[index],num)
                    actual_sub = ".".join(current_sub)
                    self.add_domain("{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix))
                    current_sub[index] = original_sub

                    #add NUM-word
                    current_sub[index] = "{}-{}".format(num,current_sub[index])
                    actual_sub = ".".join(current_sub)
                    self.add_domain("{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix))
                    current_sub[index] = original_sub

                    #add wordNUM
                    current_sub[index] = "{}{}".format(current_sub[index],num)
                    actual_sub = ".".join(current_sub)
                    self.add_domain("{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix))
                    current_sub[index] = original_sub

                    #add NUMword
                    current_sub[index] = "{}{}".format(num,current_sub[index])
                    actual_sub = ".".join(current_sub)
                    self.add_domain("{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix))
                    current_sub[index] = original_sub

                    #add wordZNUM
                    current_sub[index] = "{}0{}".format(current_sub[index],num)
                    actual_sub = ".".join(current_sub)
                    self.add_domain("{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix))
                    current_sub[index] = original_sub

                    #add ZNUMword
                    current_sub[index] = "0{}{}".format(num,current_sub[index])
                    actual_sub = ".".join(current_sub)
                    self.add_domain("{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix))
                    current_sub[index] = original_sub         


    def insert_dash_subdomains(self):
        '''
            Insert a dash between each word

            Original: example.2019.domain.com
            New #1: example.2019-dev.domain.com
            New #2: example.dev-2019.domain.com
        '''

        for line in self.domainlist:
            ext = tldextract.extract(line.strip())
            current_sub = ext.subdomain.split(".")
            if '' in current_sub:
                current_sub.remove('')
            for word in self.wordlist:
                word = word
                # if word has no length then ignore
                if len(word) == 0:
                    continue

                #for every word in our subdomain
                for index in range(len(current_sub)):
                    original_sub = current_sub[index]

                    # Version #1
                    current_sub[index] = "{}-{}".format(current_sub[index],word)
                    actual_sub = ".".join(current_sub)
                    if len(current_sub[0]) > 0 and actual_sub[:1] is not "-":
                        self.add_domain("{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix))

                    current_sub[index] = original_sub

                    # Version #2
                    current_sub[index] = "{}-{}".format(word,current_sub[index])
                    actual_sub = ".".join(current_sub)
                    if actual_sub[-1:] is not "-":
                        self.add_domain("{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix))

                    current_sub[index] = original_sub



    
    def join_words_subdomains(self):
        '''
            Add a prefix and suffix word to each subdomain

            Original: example.2019.domain.com (add word dev to 2019)
            New #1: example.2019dev.domain.com
            New #2: example.dev2019.domain.com
        '''

        for line in self.domainlist:
            ext = tldextract.extract(line.strip())
            current_sub = ext.subdomain.split(".")
            if '' in current_sub:
                current_sub.remove('')
            for word in self.wordlist:

                word = word
                # if word has no length then ignore
                if len(word) == 0:
                    continue

                for index, value in enumerate(current_sub):
                    original_sub = current_sub[index]

                    # Version #1
                    current_sub[index] = current_sub[index] + word
                    actual_sub = ".".join(current_sub)
                    self.add_domain("{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix))
                    current_sub[index] = original_sub

                    # Version #2
                    current_sub[index] = word + current_sub[index]
                    actual_sub = ".".join(current_sub)
                    self.add_domain("{0}.{1}.{2}\n".format(actual_sub, ext.domain, ext.suffix))
                    current_sub[index] = original_sub


def scan_domains(thread):
    ''' Check domain for dns record '''
    resolver = dns.resolver.Resolver()

    # Use custom dns server
    if(thread.parent.args.dnsserver is not None): 
        resolver.nameservers = [r.strip() for r in thread.parent.args.dnsserver.split(",")]

    for target in thread.domain_pool:
        #print target
        if thread.kill:
            exit(2)
        thread.parent.update_stage_progress()

        final_hostname = target.strip()
        
        # check if an A record first - if so then we look at CNAME, else move on

        result = []
        result.append(target)
        try:
            for rdata in resolver.query(final_hostname, 'CNAME'):
                result.append(rdata.target)
        except:
            pass



        if len(result) <= 1:
            try:
                A = resolver.query(final_hostname, "A")
                if len(A) > 0:
                    result = []
                    result.append(final_hostname)
                    result.append(str(A[0]))
            except:
                pass
        
        if len(result) > 1: 
            # check if we found an aws domain
            ext = tldextract.extract(str(result[1]))
            if ext.domain == "amazonaws":
                try:
                    for rdata in resolver.query(result[1], 'CNAME'):
                        result.append(rdata.target)
                except:
                    pass

            thread.update_results(result)



def main():
    args = parseArgs()
    pd = permDNS(args)

    print("{}".format(colored("---------------------\n|      permDNS      |\n---------------------","white")))
    pd.buildSubdomains()
    
    threadhandler = []

    # Removes already existing + dupes from output
    if pd.args.ignore_existing is True:
      remove_existing(pd.args)
    else:
      remove_duplicates(pd.args)

    # scan start time
    pd.start = int(time.time())

    if pd.args.resolve:
        try:
            first_run = 1
            depth = 1
            while(pd.args.scanDomains or first_run):
                print("---------------------\n| {} |\n---------------------".format(colored("Beginning Scan {} ".format(depth),"yellow")))

                first_run = 0


                # stage start time
                pd.stage_start = int(time.time())

                if pd.args.threads >= pd.domain_cnt:
                    pd.args.threads = max(pd.domain_cnt/500,1)

                # Initialise Threads
                for i in range(pd.args.threads):

                    # split wordlist up 'equally' between threads
                    newlist = []
                    for j in range(pd.domain_cnt/pd.args.threads):
                        try:
                            newlist.append(pd.domain_pool.pop())
                        except:
                            break

                    try:
                        baby = hunter(i, "Hunter-"+str(i+1), pd, newlist)
                        threadhandler.append(baby)
                        baby.start()
                    except Exception as error:
                        print("error:"),(error)

                # wake up main thread to check if abort requested
                while threadhandler:
                    time.sleep(2)
                    tmp = []
                    for t in threadhandler:
                        if t.is_alive():
                            tmp.append(t)     
                    threadhandler = tmp

                # store all results into list for later
                pd.total_results += pd.stage_results

                if pd.args.scanDomains:
                    # if no new results, finish up
                    if len(pd.stage_results) == 0:
                        break
                    
                    pd.domainlist = []
                    for result in pd.stage_results:
                        pd.domainlist.append(str(result[0]))

                    # rebuild new list for each stage
                    pd.stage_results = []

                    # reset fields
                    pd.domain_cnt = 0
                    pd.stage_progress = 0

                    timetaken = str(datetime.timedelta(seconds=(int(time.time())-pd.stage_start)))
                    # print(colored("[*] Found New Subdomains | Completed in {}".format(timetaken),"green"))
                    
                    print("---------------------\n| {} |\n---------------------".format(colored("Found Subdomains ","green")))
                    print("---------------------\n|   {}   |\n---------------------".format(colored("Time: {}".format(timetaken),"blue")))

                    # restart the timer and build new list of domainst to try #
                    pd.buildSubdomains()

                    depth += 1
                    
                    ### start scanning again! ###


            # store results to file
            for result in pd.total_results:
                pd.args.resolve.write(str(result[0]).strip() + ":" + str(result[1]).strip() + "\n")
                pd.args.resolve.flush()


            timetaken = str(datetime.timedelta(seconds=(int(time.time())-pd.start)))
            if len(pd.total_results) > 0:
                print("------------------------\n|   {}  |".format(colored("Found {} Results ".format(len(pd.total_results)),"green")))
                print("| {} |\n------------------------".format(colored("Completed in {}".format(timetaken),"green")))



            else:
                print(colored("[*] No Domains Found | Completed in {}".format(timetaken),"red"))
        
        except (KeyboardInterrupt, SystemExit):
            # kill running threads
            for t in threadhandler:
                t.kill = True

            print(colored("[*] Scan Terminated","red"))
            print(colored("[*] Terminating Threads","red"))

            # give threads a chance to stop
            while len(threadhandler) > 0:
                threadhandler.pop().join()

            # store any results that were found
            pd.total_results += pd.stage_results

            # if no new results, finish up
            if len(pd.total_results) == 0:
                print(colored("[*] No Domains Found","red"))
                exit()

            if 'y' not in raw_input(colored("[*] Do you wish to save partial results? (y/n)\n","yellow")).lower():
                print(colored("[*] No Domains Found","red"))
                exit()
            
            # store partial results to file
            for result in pd.total_results:
                pd.args.resolve.write(str(result[0]).strip() + ":" + str(result[1]).strip() + "\n")
                pd.args.resolve.flush()

            print(colored("[*] Interrupted Results have been Saved","red"))

            

if __name__ == "__main__":
    main()
