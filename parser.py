#!/usr/bin/python

import re
import sys
import urllib
import collections
import base64

with open(sys.argv[1], 'r') as f:
    read_data = f.readline()

decoded_data = base64.b64decode(read_data)
decoded_data =  decoded_data.split("&")

rules = []
ruleID = ""
ruleSrcNet = ""
ruleSrcZone = ""
ruleDestNet = ""
ruleDestZone = ""
ruleDestService = ""
ruleComment = ""
ruleAction = ""
ruleStatus = ""
rulePriority = ""
ruleClass = ""

nats = []
natID = ""
natDstOrig = ""
natSrcZone = ""
natDstTrans = ""
natSrcTrans = ""
natSvcOrig = ""
natSvcTrans = ""
natIfaceSrc = ""
natIfaceDst = ""
natPriority = ""
natComment = ""
natClass = ""

prevSrcZone = ""
prevDestZone = ""

addrGroups = {}
groupID = ""
groupObject = ""

addrObjects = {}
addrName = ""
addrIP = ""
addrSubnet = ""
addrZone = ""
addrType = ""
addrID = ""

serviceGroups = {}
sgroupID = ""
sgroupObject = ""

serviceObjects = {}
serviceID = ""
serviceName = ""
serviceStartPort = ""
serviceEndPort = ""
serviceProtocol = ""
serviceType = ""


for line in decoded_data:
    line = line.strip()
    if re.match('^policy', line):
        policyField, policyID, policyValue = re.search('^policy(.*)_(\d+)=(.*)', line).groups()
        policyID = int(policyID) + 1

        if re.match('^policyPriority', line):
            rulePriority = policyValue
        elif re.match('^policySrcZone', line):
            ruleSrcZone = policyValue
        elif re.match('^policyDstZone', line):
            ruleDestZone = policyValue
        elif re.match('^policySrcNet', line):
            if policyValue:
                ruleSrcNet = policyValue
            else:
                ruleSrcNet = "Any"
        elif re.match('^policyDstNet', line):
            if policyValue:
                ruleDestNet = policyValue
            else:
                ruleDestNet = "Any"
        elif re.match('^policyDstSvc', line):
            if policyValue:
                ruleDestService = policyValue
            else:
                ruleDestService = "Any"
        elif re.match('^policyComment', line):
            if not policyValue:
                ruleComment = "No Comment"
            else:
                ruleComment = policyValue
            if re.match('^Auto-?added|^IPv[46]', ruleComment):
                ruleClass = "Default"
            else:
                ruleClass = "Custom"
        elif re.match('^policyAction', line):
            if policyValue == "2":
                ruleAction = "Allow"
            elif policyValue == "1":
                ruleAction = "Discard"
            else:
                ruleAction = "Deny"
        elif re.match('^policyEnabled', line):
            if policyValue == "1":
                ruleStatus = "Enabled"
            else:
                ruleStatus = "Disabled"
      
        if rulePriority and ruleSrcZone and ruleDestZone and ruleSrcNet and ruleDestNet and ruleDestService and ruleAction and ruleStatus and ruleComment and ruleClass:
            # Sonicwall is goofy and has some enabled rules set to 0 when its an auto-added rule
            if re.match('^Auto', ruleComment) and ruleStatus == "Disabled":
                ruleStatus = "Enabled"

            rule = {
                "ruleID": policyID,
                "rulePriority": rulePriority,
                "ruleSrcZone": urllib.unquote(ruleSrcZone),
                "ruleDestZone": urllib.unquote(ruleDestZone),
                "ruleSrcNet": urllib.unquote(ruleSrcNet),
                "ruleDestNet": urllib.unquote(ruleDestNet),
                "ruleDestService": urllib.unquote(ruleDestService),
                "ruleAction": ruleAction,
                "ruleStatus": ruleStatus,
                "ruleComment": urllib.unquote(ruleComment),
                "ruleClass": ruleClass
            }
            rules.append(rule)
          
            rulePriority = ""
            ruleSrcZone = ""
            ruleDestZone = ""
            ruleSrcNet = ""
            ruleDestNet = ""
            ruleDestService = ""
            ruleAction = ""
            ruleComment = ""
            ruleStatus = ""
            ruleClass = ""

    if re.match('^natPolicy', line):
        policyField, policyID, policyValue = re.search('^natPolicy(.*)_(\d+) = (.*)', line).groups()
        policyID = int(policyID) + 1

        if re.match('^natPolicyPriority', line):
            natPriority = policyValue
        elif re.match('^natPolicyOrigSrc', line):
            if policyValue:
                natSrcOrig = policyValue
            else:
                natSrcOrig = "Any"
        elif re.match('^natPolicyTransSrc', line):
            if policyValue:
                natSrcTrans = policyValue
            else:
                natSrcTrans = "Original"
        elif re.match('^natPolicyOrigDst', line):
            if policyValue:
                natDstOrig = policyValue
            else:
                natDstOrig = "Any"
        elif re.match('^natPolicyTransDst', line):
            if policyValue:
                natDstTrans = policyValue
            else:
                natDstTrans = "Original"
        elif re.match('^natPolicyOrigSvc', line):
            if policyValue:
                natSvcOrig = policyValue
            else:
                natSvcOrig = "Any"
        elif re.match('^natPolicyTransSvc', line):
            if policyValue:
                natSvcTrans = policyValue
            else:
                natSvcTrans = "Original"
        elif re.match('^natPolicySrcIface', line):
            if policyValue:
                if policyValue == "18":
                    natIfaceSrc = "MGMT"
                elif policyValue == "-1":
                    natIfaceSrc = "Any"
                else:
                    natIfaceSrc = "X%s" % policyValue
        elif re.match('^natPolicyDstIface', line):
            if policyValue:
                natIfaceDst = policyValue
                if policyValue == "18":
                    natIfaceDst = "MGMT"
                elif policyValue == "-1":
                    natIfaceDst = "Any"
                else:
                    natIfaceDst = "X%s" % policyValue
        elif re.match('^natPolicyComment', line):
            if not policyValue:
                natComment = "No Comment"
            else:
                natComment = policyValue
            if re.match('^Auto-?added|^Management|^IKE', natComment):
                natClass = "Default"
            else:
                natClass = "Custom"

        if natPriority and natSrcOrig and natSrcTrans and natDstOrig and natDstTrans and natSvcOrig and natIfaceSrc and natIfaceDst and natSvcTrans and natComment:
            nat = {
                "natID": policyID,
                "natPriority": natPriority,
                "natSrcOrig": urllib.unquote(natSrcOrig),
                "natSrcTrans": urllib.unquote(natSrcTrans),
                "natDstOrig": urllib.unquote(natDstOrig),
                "natDstTrans": urllib.unquote(natDstTrans),
                "natSvcOrig": urllib.unquote(natSvcOrig),
                "natSvcTrans": urllib.unquote(natSvcTrans),
                "natIfaceSrc": natIfaceSrc,
                "natIfaceDst": natIfaceDst,
                "natComment": urllib.unquote(natComment),
                "natClass": urllib.unquote(natClass)
            }
            nats.append(nat)

            natPriority = ""
            natSrcOrig = ""
            natSrcTrans = ""
            natDstOrig = ""
            natDstTrans = ""
            natSvcOrig = ""
            natSvcTrans = ""
            natIfaceSrc = ""
            natIfaceDst = ""
            natComment = ""
            natClass = ""

    if re.match('^addro_', line):
        if re.match('^addro_atomToGrp_', line):
            groupID, groupObject = re.search('^addro_atomToGrp_(\d+)=(.*)', line).groups()
            groupObject = urllib.unquote(groupObject)
            nextPattern = "^addro_grpToGrp_"+groupID
            nextGroupPattern = nextPattern+'=(.*)'
        elif re.match(nextPattern, line):
            groupName = re.search(nextGroupPattern, line).group(1)
            groupName = urllib.unquote(groupName)
            if groupName not in addrGroups:
                addrGroups[groupName] = []
                addrGroups[groupName].append(groupObject)
            else:
                addrGroups[groupName].append(groupObject)

    if re.match('^addrObj', line):
        if re.match('^addrObjId_', line):
            addrID, addrName = re.search('^addrObjId_(.*)=(.*)', line).groups()
            addrName = urllib.unquote(addrName)
        elif re.match(str("^addrObjType_"+addrID), line):
            addrType = re.search(str("^addrObjType_"+addrID+"=(.*)"), line).group(1)
        elif re.match(str("^addrObjZone_"+addrID), line):
            addrZone = re.search(str("^addrObjZone_"+addrID+"=(.*)"), line).group(1)
            if addrZone == "":
                addrZone = "None"
        elif re.match(str("^addrObjIp1_"+addrID), line):
            addrIP = re.search(str("^addrObjIp1_"+addrID+"=(.*)"), line).group(1)
        elif re.match(str("^addrObjIp2_"+addrID), line):
            addrSubnet = re.search(str("^addrObjIp2_"+addrID+"=(.*)"), line).group(1)

        if addrID and addrName and addrType and addrZone and addrIP and addrSubnet:
            addrObjects[addrName] = {
                "addrZone": addrZone,
                "addrIP": addrIP,
                "addrSubnet": addrSubnet,
                "addrType": addrType
            }

            addrID = ""
            addrName = ""
            addrType = ""
            addrIP = ""
            addrZone = ""
            addrSubnet = ""

    if re.match('^so_', line):
        if re.match('^so_atomToGrp_', line):
            sgroupID, sgroupObject = re.search('^so_atomToGrp_(\d+) = (.*)', line).groups()
            sgroupObject = urllib.unquote(sgroupObject)
            nextsPattern = "^so_grpToGrp_"+sgroupID
            nextsGroupPattern = nextsPattern+' = (.*)'
        elif re.match(nextsPattern, line):
            sgroupName = re.search(nextsGroupPattern, line).group(1)
            sgroupName = urllib.unquote(sgroupName)
            if sgroupName not in serviceGroups:
                serviceGroups[sgroupName] = []
                serviceGroups[sgroupName].append(sgroupObject)
            else:
                serviceGroups[sgroupName].append(sgroupObject)

    if re.match('^svcObj', line):
        if re.match('^svcObjId_', line):
            serviceID, serviceName = re.search('^svcObjId_(.*) = (.*)', line).groups()
            serviceName = urllib.unquote(serviceName)
        elif re.match(str("^svcObjType_"+serviceID), line):
            serviceType = re.search(str("^svcObjType_"+serviceID+" = (.*)"), line).group(1)
        elif re.match(str("^svcObjIpType_"+serviceID), line):
            serviceProtocol = re.search(str("^svcObjIpType_"+serviceID+" = (.*)"), line).group(1)
        elif re.match(str("^svcObjPort1_"+serviceID), line):
            serviceStartPort = re.search(str("^svcObjPort1_"+serviceID+" = (.*)"), line).group(1)
        elif re.match(str("^svcObjPort2_"+serviceID), line):
            serviceEndPort = re.search(str("^svcObjPort2_"+serviceID+" = (.*)"), line).group(1)

        if serviceID and serviceName and serviceProtocol and serviceStartPort and serviceEndPort:
            if serviceType == "2":
                serviceProtocol = "N/A"
                serviceType = "Group"
                serviceEndPort = "N/A"
                serviceStartPort = "N/A"
            elif serviceType == "1":
                serviceType = "Object"
            if serviceProtocol == "17":
                serviceProtocol = "UDP"
            elif serviceProtocol == "6":
                serviceProtocol = "TCP"

            serviceObjects[serviceName] = {
                "serviceStartPort": serviceStartPort,
                "serviceEndPort": serviceEndPort,
                "serviceProtocol": serviceProtocol,
                "serviceType": serviceType
            }

            serviceID = ""
            serviceName = ""
            serviceStartPort = ""
            serviceEndPort = ""

print "===================================================================================================="
print "========== NAT Rules ==============================================================================="
print "===================================================================================================="
print ""
print "RuleID\tPriority\tSource Original\tSource Translated\tDestination Original\tDestination Translated\tService Original\tService Translated\tInterface Inbound\tInterface Outbound\tComment\tClass"
for x in nats:
    # if x["ruleSrcZone"] != prevSrcZone or x["ruleDestZone"] != prevDestZone`:`
    #     print '\n\nSource Zone: %s, Dest Zone: %s' % (x["ruleSrcZone"], x["ruleDestZone"])
    print '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' % (x["natID"], x["natPriority"], x["natSrcOrig"], x["natSrcTrans"], x["natDstOrig"], x["natDstTrans"], x["natSvcOrig"], x["natSvcTrans"], x["natIfaceSrc"], x["natIfaceDst"], x["natComment"], x["natClass"])

print ""
print "===================================================================================================="
print "========== Firewall Rules =========================================================================="
print "===================================================================================================="
print ""
print "RuleID\tPriority\tSource Zone\tDest Zone\tSource Net\tDest Net\tDest Service\tAction\tStatus\tComment\tClass"
for x in rules:
    # if x["ruleSrcZone"] != prevSrcZone or x["ruleDestZone"] != prevDestZone`:`
    #     print '\n\nSource Zone: %s, Dest Zone: %s' % (x["ruleSrcZone"], x["ruleDestZone"])
    print '%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s\t%s' % (x["ruleID"], x["rulePriority"], x["ruleSrcZone"], x["ruleDestZone"], x["ruleSrcNet"], x["ruleDestNet"], x["ruleDestService"], x["ruleAction"], x["ruleStatus"], x["ruleComment"], x["ruleClass"])
    prevSrcZone = x["ruleSrcZone"]
    prevDestZone = x["ruleDestZone"]

print ""
print "===================================================================================================="
print "========== Address Objects ========================================================================="
print "===================================================================================================="
print ""
print "Address Name\tZone\tIP\tSubnet"
oAddrObjects = collections.OrderedDict(sorted(addrObjects.items()))
for addr,addrFields in oAddrObjects.iteritems():
    print '%s\t%s\t%s\t%s' % (addr, addrFields["addrZone"], addrFields["addrIP"], addrFields["addrSubnet"])

print ""
print "===================================================================================================="
print "========== Address Groups =========================================================================="
print "===================================================================================================="
print ""
for group,groupObjects in addrGroups.iteritems():
    print group
    for groupObj in groupObjects:
        print "\t%s" % groupObj
    print ""

print ""
print "===================================================================================================="
print "========== Service Objects ========================================================================="
print "===================================================================================================="
print ""
print "Service Name\tStart Port\tEnd Port\tProtocol\tObject Type"
oServiceObjects = collections.OrderedDict(sorted(serviceObjects.items()))
for service,serviceFields in oServiceObjects.iteritems():
    print '%s\t%s\t%s\t%s\t%s' % (service, serviceFields["serviceStartPort"], serviceFields["serviceEndPort"], serviceFields["serviceProtocol"], serviceFields["serviceType"])

print ""
print "===================================================================================================="
print "========== Service Groups =========================================================================="
print "===================================================================================================="
print ""
for serviceGroup,serviceGroupObjects in serviceGroups.iteritems():
    print serviceGroup
    for serviceObj in serviceGroupObjects:
        #print serviceObj
        print "\t%s" % serviceObj
    print ""
