import gi,time
gi.require_version('Notify', '0.7')
from gi.repository import Notify,GdkPixbuf

class ResponseModule(object):
    lastMessage = None

    def __init__(self,myMAC='notSet',myIP='notSet'):
        '''Initialize all configuration variables and notification object'''
        import yaml,os

        # Load configuration data from a config file. Easily changeable
        configPath = os.path.join(os.path.dirname(__file__),'../','config/')
        self.configArray = yaml.safe_load(open(os.path.join(configPath,'installConfig.json'),'r'))
        self.userDataArray = yaml.safe_load(open(self.configArray['userDataJsonFile'],'r'))

        #Load network configs
        self.myMAC = myMAC
        self.myIP = myIP

        #Make objects for Notification
        Notify.init("ARP spoof detector")
        self.notifyObject = Notify.Notification.new("Title","Notification body")
        self.notifyObject.set_app_name("ARP spoof detector")
        self.notifyObject.set_urgency(2)

    def update_network_config(self,myMAC,myIP):
        '''Update network configs'''
        self.myMAC = myMAC
        self.myIP = myIP
        return True

    def alert_user(self,data):
        '''Create alert notification for user'''
        message = {'title':'ALERT!',
                    'message':'IP %s is being attempted to spoof from MAC %s.' % (data['pretend_ip'],data['pretend_mac']),
                    'type':'danger'}
        self.show_notification(message)
        return True

    def alert_admin(self,data):
        '''Create alert notification to send to server for admin'''
        message = data.copy() # Make a copy of object -- Python things
        message.pop('time') # Let server set the time
        message.pop('type')
        self.send_stats(message,self.configArray['serverSubmitEndPoint'])

    def show_notification(self,data):
        '''Function to display notification.
        data = {'title':'xyz','message':'message here','type':'danger|safe'}
        Notification urgency level is set to 2(max)'''

        if data.get('type') == 'danger':
            image = GdkPixbuf.Pixbuf.new_from_file(self.configArray['dangerIcon'])
        else:
            image = GdkPixbuf.Pixbuf.new_from_file(self.configArray['safeIcon'])

        notification.set_icon_from_pixbuf(image)
        self.notifyObject.update(data.get('title'),data.get('message'))
        self.notifyObject.show() #Make Notification visible
        return True

    def send_stats(self,data,endPoint):
        '''Send message to server's specified endpoint'''
        import requests
        #Send stats to server and return response status and text
        targetUrl = self.configArray['serverURL'] + endPoint
        req = requests.post(targetUrl,data=data)
        return req.text,req.status_code

    def alert(self,data):
        '''Main function called by other modules to send alert to admin and user'''
        mac = ':'.join([x.encode('hex') for x in data['arp_source_mac']])
        ip = '.'.join([str(ord(x)) for x in data['arp_source_ip']])

        attack_details = {'victim_mac':self.myMAC,
                            'victim_ip':self.myIP,
                            'pretend_mac':mac,
                            'pretend_ip':ip,
                            'employee_id':self.userDataArray['employee_id'],
                            'time':time.time(),
                            'type':'danger'}
        #Send alerts
        self.alert_user(attack_details)
        self.alert_admin(attack_details)

        #Update last message
        self.lastMessage = attack_details

        return True
