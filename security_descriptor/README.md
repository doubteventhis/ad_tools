pure vibes

parse base64 encoded nTSecurityDescriptor blobs into a human readable format. output is similair to dacledit.py. takes in a single blob or will parse a text (ldap dump) file and extract them.

```
$ python3 sdparse.py -h
usage: sdparse.py [-h] [-f PATH] [-i] [--ignore-sid SID] [sd_b64]

Decode base64 nTSecurityDescriptor(s) into human-readable form.

positional arguments:
  sd_b64                a single base64 nTSecurityDescriptor (omit when using --file)

options:
  -h, --help            show this help message and exit
  -f, --file PATH       scan a text file (e.g. an LDAP dump) for nTSecurityDescriptor blobs (AQAE/AQAU...), validate each, and parse it
  -i, --interesting-only
                        hide ACEs whose trustee is a default/builtin principal (well-known SIDs, BUILTIN groups, domain RIDs < 1000); show only admin-created principals. With --file, all-default
                        descriptors are summarised rather than printed.
  --ignore-sid SID      also treat this exact SID as default/expected (repeatable)
```

it can attempt some analysis by hiding default and built-in principals when parsing files. administrators_sd.txt is the base64 encoded ntSecurityDescriptor:
```
$ python3 sdparse.py -f administrators_sd.txt -i                    
========================================================================                                                                    
Owner   : S-1-5-21-4027830930-1768093253-4016507557-512 (Domain Admins)                                                                     
Group   : S-1-5-21-4027830930-1768093253-4016507557-512 (Domain Admins)                                                                     
Control : DACL_PRESENT, DACL_AUTO_INHERITED, SACL_AUTO_INHERITED, DACL_PROTECTED, SELF_RELATIVE  (0x9c04)                                   
                                                                      
=== Dacl (90 ACEs, 65 shown / 25 default hidden) ===                  
[00] DENY  ACCESS_DENIED_OBJECT_ACE                                   
       Trustee : S-1-5-21-4027830930-1768093253-4016507557-1118       
       Access  : DS_WRITE_PROP  (0x00000020)                          
       Object  : 00fbf30c-91fe-11d1-aebc-0000f80367c1                 
       AceFlags: CONTAINER_INHERIT_ACE                                
       ObjFlags: ACE_OBJECT_TYPE_PRESENT                                                          
[68] ALLOW ACCESS_ALLOWED_OBJECT_ACE
       Trustee : S-1-5-21-4027830930-1768093253-4016507557-1118
       Access  : FULL_CONTROL  (0x000f01ff)
       Object  : 018849b0-a981-11d2-a9ff-00c04f8eedd8
       AceFlags: CONTAINER_INHERIT_ACE
       ObjFlags: ACE_OBJECT_TYPE_PRESENT
       [!]     GenericAll / Full Control -> full object takeover
       [!]     WriteDACL -> grant yourself any right over this object
       [!]     WriteOwner -> set owner, then rewrite the DACL
[69] ALLOW ACCESS_ALLOWED_OBJECT_ACE
       Trustee : S-1-5-21-4027830930-1768093253-4016507557-1133
       Access  : FULL_CONTROL  (0x000f01ff)
       Object  : 018849b0-a981-11d2-a9ff-00c04f8eedd8
       AceFlags: CONTAINER_INHERIT_ACE
       ObjFlags: ACE_OBJECT_TYPE_PRESENT
       [!]     GenericAll / Full Control -> full object takeover
       [!]     WriteDACL -> grant yourself any right over this object
       [!]     WriteOwner -> set owner, then rewrite the DACL
[70] ALLOW ACCESS_ALLOWED_OBJECT_ACE
       Trustee : S-1-5-21-4027830930-1768093253-4016507557-1133
       Access  : FULL_CONTROL  (0x000f01ff)
       Applies : inherited by c975c901-6cea-4b6f-8319-d67f45449506
       AceFlags: CONTAINER_INHERIT_ACE, INHERIT_ONLY_ACE
       ObjFlags: ACE_INHERITED_OBJECT_TYPE_PRESENT
       [!]     GenericAll / Full Control -> full object takeover
       [!]     WriteDACL -> grant yourself any right over this object
       [!]     WriteOwner -> set owner, then rewrite the DACL
       [!]     All extended rights

```

it will also parse the entire ldap dump from tools like the ldapsearch bof (similair to bofhound). built and tested inside an ctf env. likely won't scale well.
