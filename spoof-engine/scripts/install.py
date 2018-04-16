import requests

class InstallModule(object):
    credentials = None

    def __init__(self):
        '''Initialize configArray for further work'''
        import yaml,os
        # Load configuration data from a config file. Easily changeable
        configPath = os.path.join(os.path.dirname(__file__),'../','config/')
        self.configArray = yaml.safe_load(open(os.path.join(configPath,'installConfig.json')))

    def install(self):
        '''Main install module. Fetches information from user and setup
        relavant files'''
        import pcap
        if self.get_installation_status():
            print('ARP spoof detector is already installed.')
            return False

        # Register User
        userData = self.get_user_details()
        responseText,responseStatus = self.send_to_server(userData,self.configArray['serverSignUpEndPoint'])
        if responseStatus != 200:
            print('User with same information exists.\nContact your admin for resolution.')
            exit(1)
        else:
            print('\nRegister successfull\n')

        #Get an interface from user
        networkInterface = pcap.findalldevs()
        print('\nChoose an interface to work on:')
        print("%s%s:%s"%('Interface',' '*(10-len('Interface'),'Choice')))

        for x in range(0,len(networkInterface)):
            print("%s%s:%d"%(networkInterface[x][0],' '*(10-len(networkInterface[x][0]),x+1)))

        #Validate choice
        choice = int(raw_input('Enter choice:')) -1
        while choice<0 and choice >= len(networkInterface):
            print('Incorrect choice. Try again')
            choice = int(raw_input('Enter choice:')) -1

        userData['interfaceName'] = networkInterface[choice][0]

        #Save user choice
        self.setup_file(userData)

    def get_user_details(self):
        '''Fetch login details from user. Returns a dict format object with:
        1) username
        2) email
        3) phone
        4) employee_id
        5) password'''
        from getpass import getpass
        name = raw_input('Enter your username :')
        email = raw_input('Enter your email :')
        phone = raw_input('Enter your phone number :')
        employee_id = raw_input('Enter your employee ID :')

        while True:
            pass1 = getpass('Enter password :')
            pass2 = getpass('Verify password:')

            if pass1==pas2:
                break
            print('Passwords don\'t match. Try again')

        self.credentials = {'username':name,'email':email,'phone':phone,'employee_id':employee_id,'password':pass1}
        return self.credentials

    def send_to_server(self,data,endPoint):
        '''Send data to server at provided endPoint'''
        import request
        targetUrl = self.configArray['serverURL'] + endPoint
        #Send request to server and get response
        r = request.post(targetUrl,data=data)
        return r.text,r.status_code

    def setup_file(self,data):
        '''Saves userData.json file at relevant location'''
        import json
        #Save userdata to specific file for later use
        json.dump(data,open(self.configArray['userDataJsonFile'],'w'))
        return True

    def setup_service(self,data):
        '''Reserved for creating cron job'''
        pass

    def get_installation_status(self):
        '''Finds if tool is installed or not. Return boolean value'''
        import os
        #Check if config file exists
        if os.path.exists(self.configArray['userDataJsonFile']):
            return True
        return False
