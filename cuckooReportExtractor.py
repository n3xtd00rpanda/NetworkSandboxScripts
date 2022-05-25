# author @n3xtd00rpanda @accessgroup06 & @snowball44
# Comments that aren't straight out comments are debugging flags 
# & should only be enabled when needed

from concurrent.futures import process
import os, sys
import json
from posixpath import split

def reportextractor(jsonLocation):
	print('This script will extract cuckoo generated signatures and convert it into a CSV file.\nLater it will combine signatures with cuckoo and categorize data')
	print('Please enter the path to the report you want to read signatures from. The filename is report.json found in the reports folder in the cuckoo result')
	foundyoucounter = 0
	yaracounter = 0
	domainNameList = ""
	yaraList = ""
	with open(jsonLocation, "r") as read_file:
		reportData = json.load(read_file)
		# Cuckoo signatures, retrieve
		try:
			signatureList = reportData.get('signatures')
		except ValueError:
			print('Signature error. Probably not present')
		# Domain names/hosts it tries to contact, retrieve
		try:
			domainNameList = reportData.get('behavior').get('summary').get('resolves_host')
		except ValueError:
			print("Domain error. Probably not present.")
		except AttributeError:
			print('No domains found.')
		# List of YARA rules matching for this file, retrieve
		try:
			yaraList = reportData.get('target').get('file').get('yara')
		except ValueError:
			print('YARA error. Probably not present')
		except AttributeError:
			print('No YARA rules found!')
		# List of injected processes, retrieve
		try:
			processList = reportData.get('behavior').get('processes')
		except ValueError:
			print('Error finding processes.')	
		# Print the Cuckoo signatures matched
		if signatureList is not None:
			print("Total number of signatures: ",len(signatureList))
			for signature in signatureList:
			#	print('Name of signature is: '+signature.get('name'))
			#	print('Description of signature is: '+signature.get('description'))
				# Amount of Cuckoo signatures:
			#	print('Times found is: '+ str(signature.get('markcount')))
				# Amount of times these signatures matched (1 signature can match more than once for the same analysis)
				foundyoucounter = foundyoucounter + signature.get('markcount')
			print('Total amount of times signatures were found: ',foundyoucounter)
		# Print the YARA rules that matched for this file
		if yaraList is not None:
			testlist = []
			x = 0
			print("The following YARA rules match this file:")
			for element in yaraList:
				# Store name as variable so it's easier to work with
				rulename = element.get('name')
				# print(rulename) # DEBUG // n3xdp
				# Ensure no redundancy in list
				if rulename not in testlist:
					testlist.append(rulename) # ONLY add if it doesn't already exist in the list
				# print(rulename) -- DEBUG
				# Prettifying the print-out
				#print("-------------")
				# TODO: add entries to list, then only add them if they don't already exist. AVOID DUPLICATES.
		#	print(testlist)		# Prints list of YARA rules
			print(len(testlist), "YARA rules matched for this file.\n")		# Amount of rules matched, print
		else:
			print("No YARA rules matched for this file.")	# Just in case
		
		
		if processList is not None:
			# TODO: fix this so it finds the right things from the list.
			print("The following processes were injected:\n")
			iterationcounter = 0
			for prelement in processList:
				prelementname = prelement.get('process_name')
				prelementfp = prelement.get('filepath')
		#		print(prelementname)
			#	print(type(prelementname))
			#	print(prelementfp)
				#letsgo = thisisme.split()
				#print(letsgo)
				#print(prelement)
				#print(processList[iterationcounter]['modules'][iterationcounter]['basename'])
				#print(processList[iterationcounter]['modules'][iterationcounter]['filepath'])
			#	print('\n------')
				iterationcounter = iterationcounter + 1 
			
			#print(processList[1]['modules'][1]['basename']) # DEBUG // n3xdp

			#print(processList) # -- || -- DEBUG PRINT EVERYTHING // n3xdp
			#print(type(processList[0]['modules']))

			#for prelement in range(len(processList)):
			#	print(prelement)
			#print (processList['modules'])
			#for each in processList['modules']:
			#	print(each['basename'])
			

			# Attempt 1 (remember to make processSubList a thing if u use this :)
			#processSubList = processList.get('modules')
			#for prelement in processList:
				# print(type(process.get('modules')))
			#	print(processSubList)
			#	print('Name of process is:', processSubList[prelement])
			#print(processList)

		if domainNameList is not None:
			print('\nList of domain names found')
			for domain in domainNameList:
				print('Domain is: '+ domain)
		else:
			print("No domains contacted.")

if __name__ == '__main__':
    reportextractor(sys.argv[1])
