#!/usr/bin/env python
# coding: utf-8

# #  Nessus Data Filtering using pandas 

# In[15]:


import pandas as pd

df = pd.read_csv('data.csv') #Change Filename to the name of your file
rem_none = df.loc[~(df['Risk'].isin(['None']))] #Removes rows with risk having value none
critical = rem_none.loc[rem_none['Risk'].isin(['Critical'])] #Selects rows with risk having values Critical
high = rem_none.loc[rem_none['Risk'].isin(['High'])] #Selects rows with risk having values High
medium = rem_none.loc[rem_none['Risk'].isin(['Medium'])] #Selects rows with risk having values Medium
low = rem_none.loc[rem_none['Risk'].isin(['Low'])] #Selects rows with risk having values Low

#use the below syntax to save your filtered data in csv file :
#var_name.to_csv( "file_name.csv", index=False, encoding='utf-8-sig')


# # Below Cell address the critical risk vulnerabilities :

# In[16]:


Apache_2_2_15 = critical.loc[critical['Name'].isin(['Apache 2.2.x < 2.2.15 Multiple Vulnerabilities'])]
apache_2_2_13 = critical.loc[critical['Name'].isin(['Apache 2.2.x < 2.2.13 APR apr_palloc Heap Overflow'])]
ms14 = critical.loc[critical['Name'].isin(['MS14-066: Vulnerability in Schannel Could Allow Remote Code Execution (2992611) (uncredentialed check)'])]
openssl = critical.loc[critical['Name'].isin(['OpenSSL 1.0.2 < 1.0.2g Multiple Vulnerabilities (DROWN)'])]
dellidrac = critical.loc[critical['Name'].isin(['Dell iDRAC Buffer Overflow Vulnerability (CVE-2020-5344)'])]
unsupported = critical.loc[critical['Name'].isin(['Unsupported Windows OS (remote)'])]
php = critical.loc[critical['Name'].isin(['PHP Unsupported Version Detection'])]
serv2003 = critical.loc[critical['Name'].isin(['Microsoft Windows Server 2003 Unsupported Installation Detection'])]
MS09_001 = critical.loc[critical['Name'].isin(['MS09-001: Microsoft Windows SMB Vulnerabilities Remote Code Execution (958687) (uncredentialed check)'])]
ms08_067 = critical.loc[critical['Name'].isin(['MS08-067: Microsoft Windows Server Service Crafted RPC Request Handling Remote Code Execution (958644) (ECLIPSEDWING) (uncredentialed check)'])]
win8 = critical.loc[critical['Name'].isin(['Microsoft Windows 8 Unsupported Installation Detection'])]
win10 = critical.loc[critical['Name'].isin(['Microsoft Windows 10 Version 1703 Unsupported Version Detection'])]
win_search = critical.loc[critical['Name'].isin(['Microsoft Windows Search Remote Code Execution Vulnerability (CVE-2017-8543)'])]
php_7_0_12 = critical.loc[critical['Name'].isin(['PHP 7.0.x < 7.0.12 Multiple Vulnerabilities'])]
php_7_0_16 = critical.loc[critical['Name'].isin(['PHP 7.0.x < 7.0.16 Multiple Vulnerabilities'])]
php_7_0_20 = critical.loc[critical['Name'].isin(['PHP 7.0.x < 7.0.20 Multiple Vulnerabilities'])]
microsoft_rdp = critical.loc[critical['Name'].isin(['Microsoft RDP RCE (CVE-2019-0708) (BlueKeep) (uncredentialed check)'])]
win10_1803 = critical.loc[critical['Name'].isin(['Microsoft Windows 10 Version 1803 Unsupported Version Detection'])]
ms06_040 = critical.loc[critical['Name'].isin(['MS06-040: Vulnerability in Server Service Could Allow Remote Code Execution (921883) (uncredentialed check)'])]
microsoft_iis = critical.loc[critical['Name'].isin(['Microsoft IIS 6.0 Unsupported Version Detection'])]

#Feel free to add more vulnerabilities
#Syntax ::
#Vul_name = critical.loc[critical['Name'].isin(['Vulnerability name'])]
#use the below syntax to save your filtered data in csv file :
#var_name.to_csv( "file_name.csv", index=False, encoding='utf-8-sig')


# # Below Cell address the high risk  vulnerabilities :

# In[17]:


php_7_0_9 = high.loc[high['Name'].isin(['PHP 7.0.x < 7.0.9 Multiple Vulnerabilities (httpoxy)'])]
openssl_sweet = high.loc[high['Name'].isin(['OpenSSL 1.0.2 < 1.0.2i Multiple Vulnerabilities (SWEET32)'])]
microsoft_smbv1 = high.loc[high['Name'].isin(['Microsoft Windows SMBv1 Multiple Vulnerabilities'])]
php_7_0_6 = high.loc[high['Name'].isin(['PHP 7.0.x < 7.0.6 Multiple Vulnerabilities'])]
apache_2_2_x = high.loc[high['Name'].isin(['Apache 2.2.x < 2.2.33-dev / 2.4.x < 2.4.26 Multiple Vulnerabilities'])]
php_5_2_14 = high.loc[high['Name'].isin(['PHP 5.2 < 5.2.14 Multiple Vulnerabilities'])]
apache_7_0_57 = high.loc[high['Name'].isin(['Apache Tomcat 7.0.x < 7.0.57 Multiple Vulnerabilities (POODLE)'])]
apache_2_4_39 = high.loc[high['Name'].isin(['Apache 2.4.x < 2.4.39 Multiple Vulnerabilities'])]
php_7_0_11 = high.loc[high['Name'].isin(['PHP 7.0.x < 7.0.11 Multiple Vulnerabilities'])]
php_7_0_5 = high.loc[high['Name'].isin(['PHP 7.0.x < 7.0.5 Multiple Vulnerabilities'])]
ssl_v2_3 = high.loc[high['Name'].isin(['SSL Version 2 and 3 Protocol Detection'])]
ms17_010 = high.loc[high['Name'].isin(['MS17-010: Security Update for Microsoft Windows SMB Server (4013389) (ETERNALBLUE) (ETERNALCHAMPION) (ETERNALROMANCE) (ETERNALSYNERGY) (WannaCry) (EternalRocks) (Petya) (uncredentialed check)'])]
php_7_0_4 = high.loc[high['Name'].isin(['PHP 7.0.x < 7.0.4 Multiple Vulnerabilities'])]
php_7_0_31 = high.loc[high['Name'].isin(['PHP 7.0.x < 7.0.31 Use After Free Arbitrary Code Execution in EXIF'])]
apache_2_2_12 = high.loc[high['Name'].isin(['Apache 2.2.x < 2.2.12 Multiple Vulnerabilities'])]
php_5_3_9 = high.loc[high['Name'].isin(['PHP < 5.3.9 Multiple Vulnerabilities'])]
apache_2_2_34 = high.loc[high['Name'].isin(['Apache 2.2.x < 2.2.34 Multiple Vulnerabilities'])]
dell_idrac = high.loc[high['Name'].isin(['Dell iDRAC Products Multiple Vulnerabilities (June 2018)'])]
php_7_0_19 = high.loc[high['Name'].isin(['PHP 7.0.x < 7.0.19 Multiple Vulnerabilities'])]
php_7_0_33 = high.loc[high['Name'].isin(['PHP 7.0.x < 7.0.33 Multiple vulnerabilities'])]
php_7_0_7 = high.loc[high['Name'].isin(['PHP 7.0.x < 7.0.7 Multiple Vulnerabilities'])]
php_7_0_25 = high.loc[high['Name'].isin(['PHP 7.0.x < 7.0.25 Multiple Vulnerabilities'])]
php_rcev = high.loc[high['Name'].isin(['PHP < 7.1.33 / 7.2.x < 7.2.24 / 7.3.x < 7.3.11 Remote Code Execution Vulnerability.'])]
unsupportedwebserv = high.loc[high['Name'].isin(['Unsupported Web Server Detection'])]
dell_idarc_2018 = high.loc[high['Name'].isin(['Dell iDRAC Products Multiple Vulnerabilities (Mar 2018)'])]
snmp_agent = high.loc[high['Name'].isin(['SNMP Agent Default Community Name (public)'])]
apache_2_2_14 = high.loc[high['Name'].isin(['Apache 2.2.x < 2.2.14 Multiple Vulnerabilities'])]
ssh_protocol_v = high.loc[high['Name'].isin(['SSH Protocol Version 1 Session Key Retrieval'])]
apache_ghostcat = high.loc[high['Name'].isin(['Apache Tomcat AJP Connector Request Injection (Ghostcat)'])]

#Feel free to add more vulnerabilities
#Syntax ::
#Vul_name = high.loc[critical['Name'].isin(['Vulnerability name'])]


#use the below syntax to save your filtered data in csv file :
#var_name.to_csv( "file_name.csv", index=False, encoding='utf-8-sig')


# # Sililarly we can Filter data of Medium or low risk :
# 
# "Vul_name = medium.loc[critical['Name'].isin(['Vulnerability name'])]"
# 
# "Vul_name = low.loc[critical['Name'].isin(['Vulnerability name'])]"

# In[ ]:




