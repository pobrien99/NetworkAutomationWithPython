#!/usr/bin/env python3
""" THIS PROGRAMME
1)First prototpe with ospf function
2)Functions
3)get ip,data
4) use this info to get a command

usage example:
chmod +x find_mtu.py to make executable
usage: ./find_mtu.py MTU

R1
int f0/0 = ip 192.168.0.4
int f0/1 = ip 192.168.1.1

R2
int f0/0 = ip 192.168.0.2
int f0/1 = ip 192.168.1.2

R3
int f0/0 = ip 192.168.0.3
int f0/1 = ip 192.168.1.3
"""
#f = open("syslogMsgs3.txt", "r")
#print(f.read())

import socket
import re
import netmiko
from netmiko import ConnectHandler

def main():
        syslogTuple = readData()
        syslogData ,syslogAddress = parseData(syslogTuple)
        #printMessageData(syslogData)
        syslogData=syslogData.split("%")
        syslogTime=syslogData[0]
        syslogMsg=syslogData[1]
        print('Before % = '+syslogTime)
        print('After % = '+syslogMsg)
        timestamp = findTimestamp(syslogTime)
        date = findDate(syslogTime)
        time = findTime(syslogTime)
        facilityCode = findFacilityCode(syslogMsg)
        syslogLevel = findSyslogLevel(syslogMsg)
        mnemonic = findMnemonic(syslogMsg)

        
        #OSPF = isOSPF(facilityCode)#isOspf
        #if OSPF == 'Yes':
        if isOSPF(facilityCode):
                parseOspf(syslogMsg)
                print('!!!!!!!!! MESSAGE IS OSPF RELATED')
                interface = findInterface(syslogMsg)
                syslogMessage = findSyslogMessage(syslogMsg)
                syslogIpAddress = syslogAddress[0]

#                if 'Neighbor Down' in syslogMessage:
                ospfIssue = eventRemedyOspf(syslogMessage,interface,syslogIpAddress)
                if ospfIssue =='Neighbor Down':
                        print('Up0')
                        #remedyCommand =('sh ip int br')
                        #neighborIp = OSPFneighborIp(syslogMessage)
                        #print ("Neighbor Ip = " + neighborIp)
#                        neighborIp=neighborIp.strip('Nbr ')
#                        syslogIpAddress= neighborIp ############# just for this ospf test
                        #print(neighborIp)
                        OspfNeighborIp = OSPFneighborIp(syslogMessage)
                        if OspfNeighborIp:
                                print(OspfNeighborIp)
                                ospfNeighbourIp,ospfNeighbourInterface=OspfNeighbourAddress(OspfNeighborIp)
                                sendCommand('no shut',ospfNeighbourIp,ospfNeighbourInterface)#send no shut to this interface
                        #command = eventRemedyOspf(syslogMessage,interface,syslogIpAddress)
                        
                else:
                        #syslogIpAddress=findIp(syslogAddress)
                        syslogIpAddress=syslogAddress[0]
                        print('here3')
                        command = eventRemedyOspf(syslogMessage,interface,syslogIpAddress)
                #command = eventRemedyOspf(syslogMessage)
                        if command != '':
                                #
                                #print('No Remedy detected')
                                #
                                #sendCommand(command,neighborIp,interface)
                                sendCommand(command,syslogIpAddress,interface)
                                
                        elif command == 'Neighbour command sent !':
                                print('Neighbour command sent !')
                        elif command == 'No Command to send !':
                                print('No Command to send !')

        else:

                interface = findInterface(syslogMsg)
                syslogMessage = findSyslogMessage(syslogMsg)

                syslogIpAddress=findIp(syslogAddress)
                
        #        syslogMessage,interface = printMessageData(syslogData) ##
        #        print(interface)
        #        syslogIpAddress=findIp(syslogAddress)
                command = eventRemedy(syslogMessage,interface,syslogIpAddress)
                #print("============="+command+"============")
                #print("============="+syslogMessage+"============")
        #        if command != '':
        #                sendCommand(command,syslogIpAddress,interface)
        #        else:
        #                print('no command to send')

def readData():
       
        import socket
        socket = socket.socket(socket.AF_INET, socket.SOCK_DGRAM);
        socket.bind(('', 514))
        #socket.bind(('192.168.56.107', 514))
        print('listening')
        syslogMsg = socket.recvfrom(1024)

#        syslogMsg= (b'<189>132: Jan  2 14:18:32.779: %OSPF-5-ADJCHG: Process 1, Nbr 192.168.0.1 on FastEthernet0/0 from FULL to DOWN, Neighbor Down: Dead timer expired', ('192.168.11.1', 61231))
        #syslogMsg= (b'<189>132: Jan  2 14:18:32.779: %LINEPROTO-5-UPDOWN: Line protocol on Interface FastEthernet0/0, changed state to up', ('192.168.11.1', 61231))
        #syslogMsg= (b'<189>142: Jan  2 14:24:19.579: %LINEPROTO-5-UPDOWN: Line protocol on Interface FastEthernet0/0, changed state to down', ('192.168.11.1', 61231))
        #syslogMsg= (b'<189>133: Jan  2 14:19:29.699: %SYS-5-CONFIG_I: Configured from console by console', ('192.168.11.1', 61231))
        print(str(syslogMsg))
        return syslogMsg 
        


def parseData(syslogMsg):
        # syslog is recived in a tuple, first section is the message and the second contains address'        
        syslogData = syslogMsg[0].decode('utf-8') #this is decoded as the message part is in byte format
        syslogAddress = syslogMsg[1] #contains ip and port address'

        return syslogData, syslogAddress
 

#def printMessageData(syslogData):
def findTimestamp(syslogTime):
        print(syslogTime)
        #===== FIND TIMESTAMP =====
#        #timestampRegex = re.search("\w{3}\s{1,2}\d{1,2}\s\d\d\:\d\d\:\d\d\.\d\d\d",syslogTime) #finds date
        timestampRegex = re.search("\w{3}\s\s\d{1,2}\s\d\d\:\d\d\:\d\d\.\d\d\d",syslogTime) #finds date
        #date = re.search("\w[a-z]\w[a-z]\w[a-z]\s\s\d",syslogData) #finds date
        timestamp=timestampRegex[0].strip("['")
        print(timestamp)
        return timestamp

def findDate(syslogTime):
        #===== FIND DATE =====
#        dateRegex = re.search("\w{3}\s{1,2}\d",syslogTime) #finds date
        dateRegex = re.search("\w{3}\s{1,2}\d",syslogTime) #finds date
        #date=dateRegex[0].strip("['")#this makes list
        #print(date)
        if dateRegex:
                date = dateRegex.group().strip("['")
                print(date)
                return date
        else:
                return 'JAN 0'

def findTime(syslogTime):
        #===== FIND TIME =====
        timeRegex = re.search("\d\d\:\d\d\:\d\d\.\d\d\d",syslogTime)
        #time=timeRegex[0].strip("['")
        if timeRegex:
                time=timeRegex.group().strip("['")
                print(time)
                return time
        else:
                return '00:00:00'

def findFacilityCode(syslogMsg):#===== FIND FACILITY CODE =====
        #facilityLevelRegex=re.search("\%\w{1,10}\-",syslogMsg)
        facilityLevelRegex=re.search("\w{1,10}\-",syslogMsg)
        #facilityLevel=facilityLevelRegex[0].strip("%['-")
        if facilityLevelRegex:
            facilityLevel=facilityLevelRegex.group().strip("%['-")
            print('facil level = '+facilityLevel)
            return(facilityLevel)
        else:
            #return('Null')
            print('Null')
                
def findSyslogLevel(syslogMsg):
        #===== FIND SYSLOG MESSAGE LEVEL =====  
        messageLevelRegex=re.search("\-\d\-",syslogMsg)
        #messageLevel=messageLevelRegex[0].strip("[]'-")
        if messageLevelRegex:
            messageLevel=messageLevelRegex.group().strip("[]'-")
            print(messageLevel)
            return messageLevel
        else:
            return('0')
            print('0')

def findMnemonic(syslogMsg):
        #===== FIND MNEMONIC - Text string that uniquely describes the message =====  
        #mnemonicRegex = re.search("\d\-\w{1,20}\_?\\:",syslogData)
        mnemonicRegex = re.search("\d\-\w{1,20}\_?\:",syslogMsg)
        #mnemonic = mnemonicRegex[0].strip("['-")
        if mnemonicRegex:
            mnemonic = mnemonicRegex.group().strip("['-")
            print(mnemonic)
            return mnemonic
        else:
            return('00')
            print('00')

def isOSPF(facilityLevel):#check if this messageis opsf related
        if 'OSPF' in facilityLevel:
                print('!!! THIS MESSAGE IS OSPF RELATED !!!')
                #parseOspf(syslogData)
                return 'Yes'

def findInterface(syslogMsg):
        #===== FIND INTERFACE =====
        #interfaceRegex = re.search("Interface\s\w{1,150}\/\d",syslogData)
        print(syslogMsg)
        interfaceRegex = re.search("\s\w{1,150}\d\/\d\s",syslogMsg)
        #if(interfaceRegex != ''):
        if interfaceRegex:
                #interface=interfaceRegex[0].strip(" ['-")
                interface=interfaceRegex.group().strip(" ['-")
                print(interface)
                return(interface)
        else:
                print('no interface found')
                return '##### NO interface found ####'

def findSyslogMessage(syslogMsg):
        #===== FIND SYSLOG MESSAGE =====  
        syslogMessageRegex=re.search("\,\s.{1,150}\s.{1,150}\s.{1,150}\s.{1,150}",syslogMsg)
        #if(syslogMessageRegex != ''):
        if syslogMessageRegex:
                #syslogMessage=syslogMessageRegex[0].strip("['-, ")
                syslogMessage=syslogMessageRegex.group().strip("['-, ")
                print(syslogMessage)
                return syslogMessage
        else:
                print ('no syslogMessage')
                return '##### NO syslogMessage found ####'
     

        #return syslogMessage,interface
        
def findIp(syslogAddress):
        #===== FIND IP =====  
        #print(type(syslogAddress[0]))
        syslogIpAddress= syslogAddress[0] #ip address in string format
        print(syslogIpAddress)
        #syslogIpAddress=re.search("\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",syslogIpAddress)
        #syslogIpAddress=syslogIpAddress[0].strip("['-, ")
        return syslogIpAddress

def eventRemedy(syslogMessage,interface,syslogIpAddress):
        #=========== REMEDY ======
        #print('==========')
        if 'changed state to up' in syslogMessage:
                print('Up1')
                remedyCommand =('sh ip int br')
                return remedyCommand
        elif 'changed state to down' in syslogMessage or 'changed state to administratively down' in syslogMessage:
                print("Link down on port "+str(interface))
                print("###remedyCommand = 'No shut' will be sent to "+syslogIpAddress)
                remedyCommand =('no shut')
                
                return remedyCommand
        
 #       elif 'Neighbor Down' in syslogMessage:
 #               print('Up2')
 #               remedyCommand =('sh ip int br')
 #               return remedyCommand
        else:
                #print('========= no command =======')
                print("###remedyCommand = 'do show ip int br'")
                remedyCommand =('do show ip int br')
                return remedyCommand

def eventRemedyOspf(syslogMessage,interface,syslogIpAddress):
#def eventRemedyOspf(syslogMessage):
        #=========== REMEDY ======
        #print('==========')
        if 'changed state to up' in syslogMessage:
                print('Up1')
                remedyCommand =('sh ip int br')
                return remedyCommand
        elif 'changed state to down' in syslogMessage or 'changed state to administratively down' in syslogMessage:
                print("Link down on port "+str(interface))
                print("###remedyCommand = 'No shut' will be sent to "+syslogIpAddress)
                remedyCommand =('no shut')
                
                return remedyCommand        

        elif 'Neighbor Down' in syslogMessage:
                print('Up2')
                #remedyCommand =('no shut')
                #return remedyCommand
                return 'Neighbor Down'
                
#                OspfNeighborIp = OSPFneighborIp(syslogMessage)
#                if OspfNeighborIp:
#                        print(OspfNeighborIp)
#                        OspfNeighbourAddress(OspfNeighborIp)
                        #eventRemedyOspf(syslogMessage,interface,syslogIpAddress)
#                        return 'Neighbour command sent !'

                

        else:
                #print('========= no command =======')
                print("###remedyCommand = 'do show ip int br'")
                remedyCommand =('do show ip int br')
                return 'No Command to send !'

def parseOspf(syslogData):


        #===== RETRIEVE OSPF MESSAGE =====
        ospfRegex1 = re.search("\-\w{1,150}\:\s.{1,150}",syslogData)
        #if(ospfRegex1 != ''):
        if ospfRegex1:
                #ospf1=ospfRegex1[0].strip("['-")
                ospf1=ospfRegex1.group().strip("['-")
                print(ospf1)
                return ospf1
        else:
                print('no ospf message found')
                #return 'no ospf message found'

def OSPFneighborIp(syslogMessage):
        ospfNeighborIpRegex = re.search("Nbr\s{1,2}\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}",syslogMessage)
        #if(ospfNeighborIpRegex != ''):
        if ospfNeighborIpRegex :
                #ospfNeighborIp=ospfNeighborIpRegex[0].strip("['-")
                ospfNeighborIp=ospfNeighborIpRegex.group().strip("Nbr ['-")
                print(ospfNeighborIp)
                return ospfNeighborIp

def OspfNeighbourAddress(ospfNeighborIp):
        
        #if ospfNeighborIp == '192.168.0.1':
        if ospfNeighborIp == '192.168.0.4':
                #ssh to other ip on same router to try access int of ip that dropped
                neighbourResolutionIp = '192.168.1.1' #ssh to a different interface on same neighbour router
                neighbourResolutionInterface = 'f0/0' #neighbour ip that shut was on this interface 
                #send noshut to neighbour above
                #sendCommand('no shut',neighbourResolutionIp,neighbourResolutionInterface)#send no shut to this interface
                return neighbourResolutionIp,neighbourResolutionInterface

        elif ospfNeighborIp == '192.168.1.1':
                #ssh to other ip on same router to try access int of ip that dropped
                neighbourResolutionIp = '192.168.0.1'
                neighbourResolutionInterface = 'f0/1'
                #send noshut to neighbour above
                #sendCommand('no shut',neighbourResolutionIp,neighbourResolutionInterface)#send no shut to this interface
                return neighbourResolutionIp,neighbourResolutionInterface                

        elif ospfNeighborIp == '192.168.0.2':
                #ssh to other ip on same router to try access int of ip that dropped
                neighbourResolutionIp = '192.168.1.2'
                neighbourResolutionInterface = 'f 0/0'
                #send noshut to neighbour above
                #sendCommand('no shut',neighbourResolutionIp,neighbourResolutionInterface)#send no shut to this interface
                return neighbourResolutionIp,neighbourResolutionInterface

        elif ospfNeighborIp == '192.168.1.2':
                #ssh to other ip on same router to try access int of ip that dropped
                
                neighbourResolutionIp = '192.168.0.2'
                neighbourResolutionInterface = 'f 0/1'
                print('# sending neighbour message to' +neighbourResolutionIp+' on '+neighbourResolutionInterface)
                #send noshut to neighbour above
                #sendCommand('no shut',neighbourResolutionIp,neighbourResolutionInterface)#send no shut to this interface
                return neighbourResolutionIp,neighbourResolutionInterface

        elif ospfNeighborIp == '192.168.0.3':
                #ssh to other ip on same router to try access int of ip that dropped
                neighbourResolutionIp = '192.168.1.3'
                neighbourResolutionInterface = 'f 0/0'
                #send noshut to neighbour above
                #sendCommand('no shut',neighbourResolutionIp,neighbourResolutionInterface)#send no shut to this interface
                return neighbourResolutionIp,neighbourResolutionInterface

        elif ospfNeighborIp == '192.168.1.3':
                #ssh to other ip on same router to try access int of ip that dropped
                neighbourResolutionIp = '192.168.0.3'
                neighbourResolutionInterface = 'f 0/1'
                #send noshut to neighbour above
                #sendCommand('no shut',neighbourResolutionIp,neighbourResolutionInterface)#send no shut to this interface
                return neighbourResolutionIp,neighbourResolutionInterface                

def sendCommand(command,syslogIpAddress,interface):
#def sendCommand():
        #print('-------------en conf t , int ='+interface+' ,cmd= '+command + ',ip = ' + syslogIpAddress)
        iosv_l2 = {
        'device_type': 'cisco_ios',
       'ip':   syslogIpAddress.strip(),
#        'ip':   '192.168.0.55',
        'username': 'admin',
        'password': 'cisco',
#        'secret': 'class',
        'secret': 'cisco',
        }
        net_connect =ConnectHandler(**iosv_l2)
        print('####  SSHING TO '+syslogIpAddress +' ####')
        # Call 'enable()' method to elevate privileges
        net_connect.enable()

        output =net_connect.send_command('show ip int brief')
        print(output)
        print(syslogIpAddress)
        print(interface)
        #find promt , catch #
        output =net_connect.send_command("Conf t", expect_string=r"R2")
        #net_connect.send_command('conf t')
        print('###sending  '+ 'int '+ interface)
        output = net_connect.send_command_timing('int '+ interface)#,expect_string =R"R2\(config\)\#")
        print(output)
        output =net_connect.send_command_timing(command)#,expect_string =R"R2\(config\)\#")
        #output =net_connect.send_command('no shut')
#        print(output)
        #print('-------------en +'+'conf t ,'+ 'int '+ interface+' , '+command)    
        print('-------------')
        net_connect.send_command_timing('end')
        net_connect.disconnect()
        print('-------------')

        
# standard boilerplate to call main().
if __name__ == "__main__":
        #while(1):
        main()

