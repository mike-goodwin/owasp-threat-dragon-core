'use strict';

var nools = require('nools');

function threatengine() {

var flowName = 'threat generation';

var service = {
generateForElement: generateForElement,
generateForElementInContext: generateForElementInContext,
generateForGraph: generateForGraph
};

var Threats = function () {
this.collection = [];
};

var Element = function (element) {
this.element = element;
};

//Checks whether the values (within a string) of a dropdown element = the selected value)
//E.g. Returns boolean for  stringOfOptions:"car, van, truck", selectedValue in the dropdown = car, hence will return true
//E.g. Returns boolean for  stringOfOptions:"car, van", selectedValue in the dropdown = suv, hence will return false
function dropDownOptionsCheck(elementId, stringOfOptions) {
var selectedElement = document.getElementById(elementId);
if (!selectedElement) {
    return false;
}
var selectedValue = selectedElement.options[selectedElement.selectedIndex].value;
return stringOfOptions.includes(selectedValue);
}

return service;

function generateForElement(element) {
//todo: implement proper rule set

var flow = initialiseFlow(flowName);
var threats = new Threats();
var el = new Element(element);
var session = flow.getSession(threats, el);
return session.match().then(function () {
    session.dispose();
    nools.deleteFlow(flowName);
    return threats.collection;
});
}

function generateForElementInContext() {
//todo
return [];
}

function generateForGraph() {
//todo
return [];
}

function initialiseFlow(flowName) {
return nools.flow(flowName, function (flow) {

    flow.rule('Proper Classification of Medical Device ',[[Element, 'el','el.element.attributes.type == "tm.SmartWatch" || el.element.attributes.type== "tm.Pacemaker" || el.element.attributes.type == "tm.Electrocardiogram"|| el.element.attributes.type == "tm.MobilePhone" ||el.element.attributes.type == "tm.Laptop" || el.element.attributes.type =="tm.Tablet"'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '0.1',
            title:'Proper Classification of Medical Device ',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Federal Governments provide different classifications and requirements formedical devices.When building a medical device, it is important to classify the device you arebuilding to ensure the system meets standards defined by the mainregulatory body in your operating regions.The threat Your system/device will fail certification.',
            mitigation:'Classify your eHealth device before development. Consult the mostrecent guidance documents provided by the Government of Canada toaid in classifying your device and understanding the systemicrequirements.',
            references:[]});});

    flow.rule('Compliance in the Collection and Storage of Electronic Health Records',[[Element, 'el','el.element.attributes.type == "tm.SmartWatch" ||el.element.attributes.type == "tm.Pacemaker" || el.element.attributes.type== "tm.Electrocardiogram" || el.element.attributes.type =="tm.MobilePhone" || el.element.attributes.type == "tm.Laptop" ||el.element.attributes.type == "tm.Tablet"'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '0.2',
            title:'Compliance in the Collection and Storage of Electronic Health Records',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Depending on the nation and region of subject data collection and storage(local or remote), specific operating rules may apply.For example: In the storage of electronic health records in Canada, specificrules and legislation are put into place varying by province/territory andcontinuously change over time. The legislation is written through discussionof principles of consent to collection, limited use, security safeguards, andpatient participation.',
            mitigation:'Legal council is required when defining User Agreements and whenengineering specific rules of collection or storage to ensure all definedstandards and criterion are met for the region(s) of operation.',
            references:[]});});

    flow.rule('CDP Manipulation',[[Element, 'el','el.element.attributes.type =="tm.Process" && isTrue(el.element.isANetworkSwitch)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '0.3',
            title:'CDP Manipulation',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'CDP Manipulation: CDP packets are enabled onall interfaces by default on Cisco switches andthey are transmitted in clear text which allows anattacker to analyze the packets and gain a wealthof information about the network device then theattacker can use this information to execute aknown vulnerability against the device platform.',
            mitigation:'Solution is to disable CDP on non-management interfaces.',
            references:[]});});

    flow.rule('MAC Flooding',[[Element, 'el','el.element.attributes.type =="tm.Process" && isTrue(el.element.isANetworkSwitch)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '0.4',
            title:'MAC Flooding',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'MAC Flooding: Here the attacker floods the CAMtable with MAC addresses more than the switchcan store which leads to the switch operating ashub giving the attacker the opportunity to sniff alltraffic on the segment.',
            mitigation:'Configuring Port Security: It involves limitingthe NO. of MACs allowed through a port andcan also specify what is the MAC/MACs are.,the switch port have to be in access mode,when a violation occurs one of 3 actions istaken based on your configuration (shutdown,protect and restrict). the default action is toshut down the port and a log message willappear, protect means ignore the violatedMAC but there is no way to tell us that aviolation had occurred, restrict is the same asprotect but it adds a counter to the violationcounter and a log message will appear also. ifa port is shut down due to violation it has tobe manually re opened using the shutdownand no shutdown commands in the samesequence or using the (config)#errdisablerecovery cause security-violation then to setthe recover interval (config)#errdisablerecovery interval {time in sec} and to verifythe error disable recovery state #sh errdisablerecovery.ii- Port Base Authentication or 80',
            references:[]});});

    flow.rule('VLAN Based Attacks',[[Element, 'el','el.element.attributes.type =="tm.Process" && isTrue(el.element.isANetworkSwitch)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '0.5',
            title:'VLAN Based Attacks',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'VLAN hopping: Is when a station is able to accessVLAN other than its own. This can be donethrough one of the following: A- Switch spoofing:A PC will claim to establish a trunk link betweenitself and the switch and gain all the VLANinformations trying to get benefit of the switchdefault interfaces state (dynamic auto/desirable).802.1q Double tagging: Here the attackercomputer double tags the frame with the nativeVLAN on its trunk link and the second tag is forthe destined victim VLAN, when the framereaches the first switch it\'s rips off the first tagand forward it to all the trunk links configured forthe native VLAN and when it reaches the secondswitch it will see the second tag and forward thefame to the victim VLAN.',
            mitigation:'VLAN Hopping:  I- Disable the DTPmessages on trunk ports (using no negotiate),and avoid the switch defaults (dynamicauto/desirable) regarding trunk links aspossible, better is to hardcode the ports. ii-Configure all the ports that should connect toend stations as access, assign them to anunused VLAN and shut them down.Double Tagging:I- The same steps as the switch spoofing. ii-Configuring VACL (VLAN Access ControlList). iii- Private VLAN, PVLANs allows youto divide a VLAN into secondary VLANs,letting you isolate a set of ports from otherports within the same VLAN, we create aprimary VLAN and a secondary VLANs asdesired, we can have one isolated per primarybut we can have as many ports in the isolatedas desired, private VLAN can only beconfigured on switches in transparent VTPmode, ports within private VLAN can be oneof three: - Community: communicates withother community ports and promiscuousports. - Isolated: communicates withpromiscuous only.- Promiscuous: communicates with all ports.',
            references:[]});});

    flow.rule('Empty String Password',[[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials) && isTrue(el.element.remoteMedicalRecordStorage)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '1.1',
            title:'Empty String Password',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Using an empty string as a password is insecure.It is never appropriate to use an empty string as a password. It is too easy toguess. An empty string password makes the authentication as weak with theuser names which are normally public or guessable. This makes a brute-forceattack against the login interface much easier.',
            mitigation:'To counter this threat, a password that is not an empty string should beused. Users are suggested to have passwords with at least eight characterslong. It is not appropriate to have an empty string as a password [79].',
            references:[{name:'CWE-258: Empty Password in Configuration File', link:'https://cwe.mitre.org/data/definitions/258.html'}]});});

    flow.rule('Password in Configuration File',[[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials) && isTrue(el.element.checkboxRemoteMedicalRecordStorage)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '1.2',
            title:'Password in Configuration File',
            type:'Information disclosure',
            status:'Open',
            severity:'Medium',
            description:'Storing a password in a configuration file allows anyonewho can read the file access to the password-protectedresource. Developers sometimes believe that they cannotdefend the application from someone who has access tothe configuration, but this attitude makes an attacker\'s jobeasier.',
            mitigation:'To mitigate this threat, 2 mitigations are required.The configuration file needs to employ a form of AccessControl to ensure only those who have the privilege toaccess that file, are the only ones allowed to access that [2].To control the information contained in the configurationfile, the passwords should be stored in encrypted textwhich will combine the use of hash functions and the use ofsalts to take any password of any size and produce a uniquehash value of the password and combine it with the originalpassword, that way the password cannot be determinedfrom the file [2].',
            references:[{name:'Advances of Password Cracking and Countermeasures in Computer Security', link:'https://arxiv.org/pdf/1411.7803.pdf'}]});});

    flow.rule('Hardcoded Password',[[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials) && isTrue(el.element.checkboxRemoteMedicalRecordStorage)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '1.3',
            title:'Hardcoded Password',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Hardcoded passwords may compromise system security in a way that cannotbe easily remedied.It is never a good idea to hardcode a password. Not only does hardcoding apassword allow all the project\'s developers to view the password, it alsomakes fixing the problem extremely difficult. Once the code is in production,the password cannot be changed without patching the software. If theaccount protected by the password is compromised, the owners of thesystem will be forced to choose between security and availability.',
            mitigation:'To counter this threat of hardcoding passwords, there are severalmitigations/countermeasures that can be implemented:Ask user for the password. The program should not know the password of auser. The user should be presented with a challenge to enter their passwordfor the program to not be compromised easily [5].If an existing password is stored on an Authentication distributed server suchas an AFS (Andrew Filesystem [6]) or Kerberos, obtain the passwords fromthe server [5].Have the password stored in a separate configuration file, where that file isstrictly read access only and has a level of access control that only certainindividuals and processes who have the right privilege can read the file [5].',
            references:[{name:'Alternatives to Hardcoding Passwords', link:'https://security.web.cern.ch/security/recommendations/en/password_alternatives.shtml'},{name:'AFS: The Andrew Filesystem', link:'https://stuff.mit.edu/afs/sipb/project/doc/guide/guide/node12.html'}]});});

    flow.rule('Password Plaintext Storage',[[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentialsStore)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '1.4',
            title:'Password Plaintext Storage',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Storing a password in plaintext may result in asystem compromise.Password management issues occur when apassword is stored in plaintext in anapplication\'s properties or configuration file. Aprogrammer can attempt to remedy thepassword management problem by obscuring thepassword with an encoding function, such asbase 64 encoding, but this effort does notadequately protect the password.',
            mitigation:'Passwords should never be stored in plain text.Rather these passwords should be stored inencrypted text which will combine the use ofhash functions and the use of salts to take anypassword of any size and produce a unique hashvalue of the password and combine it with theoriginal password, that way the password cannotbe determined from the file. [2]',
            references:[{name:'Advances of Password Cracking and Countermeasures in Computer Security', link:'https://arxiv.org/pdf/1411.7803.pdf'}]});});

    flow.rule('Least Privilege Violation',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) || (el.element.attributes.type==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.privilegeLevelForMobilePhone)) ||(el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) || (el.element.attributes.type =="tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '1.5',
            title:'Least Privilege Violation',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The elevated privilege level required to perform operations such as chroot()should be dropped immediately after the operation is performed.When a program calls a privileged function, such as chroot(), it must firstacquire root privilege. As soon as the privileged operation has completed,the program should drop root privilege and return to the privilege level ofthe invoking user.',
            mitigation:'There are several ways to mitigate the least privilege violation:Split an individual components into several components, and assignlower privilege levels to those components [8].Identify areas in the system which have that elevated privilege anduse those  components instead to accomplish the task [8].Create a separate environment within the system/program whereonly within that area or environment has an elevated privilege [8].',
            references:[{name:'CWE-272: Least Privilege Violation', link:'https://cwe.mitre.org/data/definitions/272.html'}],
            examples:[{
                language: {name: 'C', highlightAlias: 'c'},
                preText: 'The following example demonstrates the weakness.',
                code: 'setuid(0);\n' +
                    '// Do some important stuff \n' +
                    'setuid(old_uid);\n' +
                    '// Do some non privileged stuff.'
            },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following code calls chroot() to restrict the application to a subset of the filesystem below APP_HOME in order to prevent an attacker from using the program to gain unauthorized access to files located elsewhere. The code then opens a file specified by the user and processes the contents of the file.',
                    postText: 'Constraining the process inside the application\'s home directory before opening any files is a valuable security measure. However, the absence of a call to setuid() with some non-zero value means the application is continuing to operate with unnecessary root privileges. Any successful exploit carried out by an attacker against the application can now result in a privilege escalation attack because any malicious operations will be performed with the privileges of the superuser. If the application drops to the privilege level of a non-root user, the potential for damage is substantially reduced.',
                    code: 'chroot(APP_HOME);\n' +
                        'chdir("/");\n' +
                        'FILE* data = fopen(argv[1], "r+");\n' +
                        '...'
                }]
        });});

    flow.rule('Code Permission',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.privilegeLevelForProcess)) || (el.element.attributes.type==  "tm.Actor" && isFalse(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isFalse(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isFalse(el.element.privilegeLevelForMobilePhone)) ||(el.element.attributes.type == "tm.Pacemaker" && isFalse(el.element.privilegeLevelForPacemaker)) || (el.element.attributes.type =="tm.SmartWatch" && isFalse(el.element.privilegeLevelForSmartWatch)) ||(el.element.attributes.type == "tm.Laptop" && isFalse(el.element.privilegeLevelForLaptop)) || (el.element.attributes.type =="tm.Tablet" && isFalse(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isFalse(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '1.6',
            title:'Code Permission',
            type:'Elevation of privilege, Information Disclosure',
            status:'Open',
            severity:'High',
            description:'An active developer with access to unrelated module code may tamper ordisclose sensitive project information (Interproject Code Access).',
            mitigation:'Throughout the development lifecycle, there are several mitigations that canbe used:Within the Implementation phase, if a critical resource is being used, thereshould be a check to see if a resource has permissions/behavior which are notsecure (such as a regular user being able to modify that resource). If there aresuch behaviors or permissions that exist, the program should create an erroror exit the program [10].Within the Architecture and Design phase, one should split up the softwarecomponents based on privilege level and if possible, control what data,functions and resources each component uses based the privilege level [10].Another option in this phase is to create a separate environment within thesystem/program where only within that area or environment has an elevatedprivilege [8].In the installation phase, default or most restrictive permissions should be setto avoid any code which doesn\'t have the permissions to be run. Also, theassumption that a system administrator will change the settings based on amanual is incorrect [10].In the System Configuration phase, The configurable, executable files andlibraries should be only have read and write access by the systemadministrator [10].In the Documentation phase, within any documentation, any configurationsthat are suggested must be secure, and do not affect the operation of thecomputer or program [10].',
            references:[{name:'CWE-272: Least Privilege Violation', link:'https://cwe.mitre.org/data/definitions/272.html'},{name:'CWE-732: Incorrect Permission Assignment for Critical Resource', link:'https://cwe.mitre.org/data/definitions/732.html'}],
            examples:[{
                language: {name: 'C', highlightAlias: 'c'},
                preText: 'The following example demonstrates the weakness.',
                code: 'setuid(0);\n' +
                    '// Do some important stuff \n' +
                    'setuid(old_uid);\n' +
                    '// Do some non privileged stuff.'
            },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following code calls chroot() to restrict the application to a subset of the filesystem below APP_HOME in order to prevent an attacker from using the program to gain unauthorized access to files located elsewhere. The code then opens a file specified by the user and processes the contents of the file.',
                    postText: 'Constraining the process inside the application\'s home directory before opening any files is a valuable security measure. However, the absence of a call to setuid() with some non-zero value means the application is continuing to operate with unnecessary root privileges. Any successful exploit carried out by an attacker against the application can now result in a privilege escalation attack because any malicious operations will be performed with the privileges of the superuser. If the application drops to the privilege level of a non-root user, the potential for damage is substantially reduced.',
                    code: 'chroot(APP_HOME);\n' +
                        'chdir("/");\n' +
                        'FILE* data = fopen(argv[1], "r+");\n' +
                        '...'
                },
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following code sets the umask of the process to 0 before creating a file and writing "Hello world" into the file.',
                    postText: 'After running this program on a UNIX system, running the "ls -l" command might return the following output: -rw-rw-rw- 1 username 13 Nov 24 17:58 hello.out The "rw-rw-rw-" string indicates that the owner, group, and world (all users) can read the file and write to it.',
                    code: '#define OUTFILE "hello.out"\n' +
                        '\n' +
                        'umask(0);\n' +
                        'FILE *out;\n' +
                        '/* Ignore CWE-59 (link following) for brevity */ \n' +
                        '\n' +
                        'out = fopen(OUTFILE, "w");\n' +
                        'if (out) {\n' +
                        'fprintf(out, "hello world!\\n");\n' +
                        'fclose(out);\n' +
                        '}'
                },
                {
                    language: {name: 'PHP', highlightAlias: 'php'},
                    preText: 'This code creates a home directory for a new user, and makes that user the owner of the directory. If the new directory cannot be owned by the user, the directory is deleted.',
                    postText: 'Because the optional "mode" argument is omitted from the call to mkdir(), the directory is created with the default permissions 0777. Simply setting the new user as the owner of the directory does not explicitly change the permissions of the directory, leaving it with the default. This default allows any user to read and write to the directory, allowing an attack on the user\'s files. The code also fails to change the owner group of the directory, which may result in access by unexpected groups.',
                    code: 'function createUserDir($username){\n' +
                        '$path = \'/home/\'.$username;\n' +
                        'if(!mkdir($path)){\n' +
                        'return false;\n' +
                        '}\n' +
                        'if(!chown($path,$username)){\n' +
                        'rmdir($path);\n' +
                        'return false;\n' +
                        '}\n' +
                        'return true;\n' +
                        '}'
                },
                {
                    language: {name: 'Perl', highlightAlias: 'perl'},
                    preText: 'The following code snippet might be used as a monitor to periodically record whether a web site is alive. To ensure that the file can always be modified, the code uses chmod() to make the file world-writable.',
                    postText: 'The first time the program runs, it might create a new file that inherits the permissions from its environment. A file listing might look like: -rw-r--r-- 1 username 13 Nov 24 17:58 secretFile.out This listing might occur when the user has a default umask of 022, which is a common setting. Depending on the nature of the file, the user might not have intended to make it readable by everyone on the system.\n' +
                        '\n' +
                        'The next time the program runs, however - and all subsequent executions - the chmod will set the file\'s permissions so that the owner, group, and world (all users) can read the file and write to it: -rw-rw-rw- 1 username 13 Nov 24 17:58 secretFile.out Perhaps the programmer tried to do this because a different process uses different permissions that might prevent the file from being updated.',
                    code:'$fileName = "secretFile.out";\n' +
                        '\n' +
                        'if (-e $fileName) {\n' +
                        'chmod 0777, $fileName;\n' +
                        '}\n' +
                        '\n' +
                        'my $outFH;\n' +
                        'if (! open($outFH, ">>$fileName")) {\n' +
                        'ExitError("Couldn\'t append to $fileName: $!");\n' +
                        '}\n' +
                        'my $dateString = FormatCurrentTime();\n' +
                        'my $status = IsHostAlive("cwe.mitre.org");\n' +
                        'print $outFH "$dateString cwe status: $status!\\n";\n' +
                        'close($outFH);'
                },
                {
                    language: {name: 'Bash', highlightAlias: 'bash'},
                    preText: 'The following command recursively sets world-readable permissions for a directory and all of its children:',
                    postText: 'If this command is run from a program, the person calling the program might not expect that all the files under the directory will be world-readable. If the directory is expected to contain private data, this could become a security problem.',
                    code: 'chmod -R ugo+r DIRNAME'
                }
            ]
        });});

    flow.rule('Double Free Error',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","c, c++, assembly"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "c, c++, assembly"))) || (el.element.attributes.type == "tm.SmartWatch"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "c, c++, assembly"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","c, c++, assembly"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "c,c++, assembly"))) || (el.element.attributes.type ==  "tm.Electrocardiogram"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "c, c++, assembly"))) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "c, c++, assembly")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.1',
            title:'Double Free Error',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'Double free errors occur when free() is called more than once with the samememory address as an argument.Calling free() twice on the same value can lead to memory leak. When aprogram calls free() twice with the same argument, the program\'s memorymanagement data structures become corrupted and could allow a malicioususer to write values in arbitrary memory spaces. This corruption can causethe program to crash or, in some circumstances, alter the execution flow. Byoverwriting registers or memory spaces, an attacker can trick the programinto executing code of his/her own choosing, often resulting in an interactiveshell with elevated permissions.When a buffer is free(), a linked list of free buffers is read to rearrange andcombine the chunks of free memory (to be able to allocate larger buffers inthe future). These chunks are laid out in a double linked list which points toprevious and next chunks. Unlinking an unused buffer (which is whathappens when free() is called) could allow an attacker to write arbitraryvalues in memory; essentially overwriting valuable registers, callingshellcode from its own buffer.',
            mitigation:'To mitigate this threat, each allocation should only be freed once. Once thememory has been allocated, the pointer should be set to NULL to ensure thepointer cannot be freed again. In complicated error conditions, ensure thatclean-up routines represent the state of allocation. If the language is objectoriented, that object destructors delete each allocation of memory one timeonly [11].',
            references:[{name:'Doubly freeing memory', link:'https://www.owasp.org/index.php/Doubly_freeing_memory'}],
            examples:[{
                language: {name: 'C', highlightAlias: 'c'},
                preText: 'While contrived, this code should be exploitable on Linux distributions that don\'t ship with heap-chunk check summing turned on.',
                postText: 'Double free vulnerabilities have three common (and sometimes overlapping) causes:\n' +
                    '\n' +
                    'Error conditions and other exceptional circumstances\n' +
                    'Usage of the memory space after it\'s freed.\n' +
                    'Confusion over which part of the program is responsible for freeing the memory\n' +
                    'Although some double free vulnerabilities are not much more complicated than the previous example, most are spread out across hundreds of lines of code or even different files. Programmers seem particularly susceptible to freeing global variables more than once.',
                code: '#include <stdio.h>\n' +
                    '#include <unistd.h>\n' +
                    '\n' +
                    '#define BUFSIZE1    512\n' +
                    '#define BUFSIZE2    ((BUFSIZE1/2) - 8)\n' +
                    '\n' +
                    'int main(int argc, char **argv) { \n' +
                    '  char *buf1R1;    \n' +
                    '  char *buf2R1;    \n' +
                    '  char *buf1R2;    \n' +
                    '\n' +
                    '  buf1R1 = (char *) malloc(BUFSIZE2);    \n' +
                    '  buf2R1 = (char *) malloc(BUFSIZE2);    \n' +
                    '  \n' +
                    '  free(buf1R1);    \n' +
                    '  free(buf2R1);    \n' +
                    '\n' +
                    '  buf1R2 = (char *) malloc(BUFSIZE1);    \n' +
                    '  strncpy(buf1R2, argv[1], BUFSIZE1-1);    \n' +
                    '  \n' +
                    '  free(buf2R1);    \n' +
                    '  free(buf1R2);\n' +
                    '}'
            }]
        });});

    flow.rule('Leftover Debug Code',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.SmartWatch")|| (el.element.attributes.type =="tm.PaceMaker") || (el.element.attributes.type== "tm.Electrocardiogram") ||(el.element.attributes.type =="tm.MobilePhone") ||(el.element.attributes.type == "tm.Laptop") ||(el.element.attributes.type == "tm.Tablet")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.2',
            title:'Leftover Debug Code',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'Debug code can create unintended entry pointsin a deployed web application.A common development practice is to add \"backdoor\" code specifically designed for debuggingor testing purposes that is not intended to beshipped or deployed with the application. Whenthis sort of debug code is accidentally left in theapplication, the application is open to unintendedmodes of interaction. These back-door entrypoints create security risks because they are notconsidered during design or testing and falloutside of the expected operating conditions ofthe application.',
            mitigation:'To mitigate this threat, all debug code should beremoved prior to delivery of code [12].',
            references:[{name:'CWE-489: Leftover Debug Code', link:'https://cwe.mitre.org/data/definitions/489.html'}],
            examples:[
                {
                    language: {name: 'Markup', highlightAlias: 'markup'},
                    preText: 'Debug code can be used to bypass authentication. For example, suppose an application has a login script that receives a username and a password. Assume also that a third, optional, parameter, called "debug", is interpreted by the script as requesting a switch to debug mode, and that when this parameter is given the username and password are not checked. In such a case, it is very simple to bypass the authentication process if the special behavior of the application regarding the debug parameter is known. In a case where the form is:',
                    postText: 'Then a conforming link will look like:\n' +
                        '\n' +
                        '(informative)\n' +
                        ' \n' +
                        'http://TARGET/authenticate_login.cgi?username=...&password=...\n' +
                        'An attacker can change this to:\n' +
                        '\n' +
                        '(attack code)\n' +
                        ' \n' +
                        'http://TARGET/authenticate_login.cgi?username=&password=&debug=1\n' +
                        'Which will grant the attacker access to the site, bypassing the authentication process.',
                    code: '<FORM ACTION="/authenticate_login.cgi">\n' +
                        '<INPUT TYPE=TEXT name=username>\n' +
                        '<INPUT TYPE=PASSWORD name=password>\n' +
                        '<INPUT TYPE=SUBMIT>\n' +
                        '</FORM>'
                }
            ]
        });});

    flow.rule('Memory Leak',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess", "c, c++"))) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "c, c++"))) ||(el.element.attributes.type == "tm.SmartWatch"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforSmartWatch", "c, c++"))) ||(el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforLaptop", "c, c++"))) ||(el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforTablet", "c, c++"))) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforElectrocardiogram", "c, c++")))|| (el.element.attributes.type == "tm.Pacemaker"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforPacemaker", "c, c++")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.3',
            title:'Memory Leak',
            type:'Denial of service',
            status:'Open',
            severity:'High',
            description:'A memory leak is an unintentional form ofmemory consumption whereby the developerfails to free an allocated block of memory whenno longer needed. The consequences of such anissue depend on the application itself. Considerthe following general three cases:Short Lived User-land Application: Little if anynoticeable effect. Modern operating systemrecollects lost memory after programtermination.Long Lived User-land Application: Potentiallydangerous. These applications continue to wastememory over time, eventually consuming all RAMresources. Leads to abnormal system behavior.Kernel-land Process: Memory leaks in the kernellevel lead to serious system stability issues.Kernel memory is very limited compared to userland memory and should be handled cautiously.Memory is allocated but never freed. Memoryleaks have two common and sometimesoverlapping causes:Error conditions and other exceptionalcircumstances.Confusion over which part of the program isresponsible for freeing the memory.Most memory leaks result in general softwarereliability problems, but if an attacker canintentionally trigger a memory leak, the attackermight be able to launch a denial of service attack(by crashing the program) or take advantage ofother unexpected program behavior resultingfrom a low memory condition.',
            mitigation:'To mitigate that threat, 3rd party tools/softwareare required to see if this vulnerability exists inthe code. One such tool that can be used in aUnix/Linux environment is a program calledValgrind. This program will run the desiredsoftware program to be checked to check allmemory allocation and de-allocation methodsare working as intended. [13]',
            references:[{name:'Memory leak', link:'https://www.owasp.org/index.php/Memory_leak'}],
            examples:[
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following example is a basic memory leak in C:',
                    postText: 'In this example, we have 10 allocations of size MAXSIZE. Every allocation, with the exception of the last, is lost. If no pointer is pointed to the allocated block, it is unrecoverable during program execution. A simple fix to this trivial example is to place the free() call inside of the \'for\' loop. Refer to the following link for a real world example of a memory leak causing denial of service: https://securiteam.com/securitynews/5ZP0M1PIUI/',
                    code: '#include <stdlib.h>\n' +
                        '#include <stdio.h>\n' +
                        '\n' +
                        '#define  LOOPS    10\n' +
                        '#define  MAXSIZE  256\n' +
                        '\n' +
                        'int main(int argc, char **argv)\n' +
                        '{\n' +
                        '     int count = 0;\n' +
                        '     char *pointer = NULL;\n' +
                        '\n' +
                        '     for(count=0; count<LOOPS; count++) {\n' +
                        '          pointer = (char *)malloc(sizeof(char) * MAXSIZE);\n' +
                        '     }\n' +
                        '\n' +
                        '     free(pointer);\n' +
                        '\n' +
                        '     return count;\n' +
                        '}'
                },
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following C function leaks a block of allocated memory if the call to read() fails to return the expected number of bytes:',
                    code: 'char* getBlock(int fd) {\n' +
                        '\tchar* buf = (char*) malloc(BLOCK_SIZE);\n' +
                        '\tif (!buf) {\n' +
                        '\t  return NULL;\n' +
                        '\t}\n' +
                        '\tif (read(fd, buf, BLOCK_SIZE) != BLOCK_SIZE) {\n' +
                        '\t  return NULL;\n' +
                        '\t}\n' +
                        '\treturn buf;\n' +
                        '\t}'
                }
            ]
        });});

    flow.rule('Null Dereference',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.SmartWatch")|| (el.element.attributes.type =="tm.PaceMaker") || (el.element.attributes.type== "tm.Electrocardiogram") ||(el.element.attributes.type =="tm.MobilePhone") ||(el.element.attributes.type == "tm.Laptop") ||(el.element.attributes.type == "tm.Tablet")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.4',
            title:'Null Dereference',
            type:'Denial of service',
            status:'Open',
            severity:'Medium',
            description:'The program can potentially dereference a nullpointer, thereby raising a NullPointerException.Null pointer errors are usually the result of one ormore programmer assumptions being violated.Most null pointer issues result in generalsoftware reliability problems, but if an attackercan intentionally trigger a null pointerdereference, the attacker might be able to usethe resulting exception to bypass security logic orto cause the application to reveal debugginginformation that will be valuable in planningsubsequent attacks.A null-pointer dereference takes place when apointer with a value of NULL is used as though itpointed to a valid memory area.Null-pointer dereferences, while common, cangenerally be found and corrected in a simple way.They will always result in the crash of theprocess, unless exception handling (on someplatforms) is invoked, and even then, little can bedone to salvage the process.',
            mitigation:'To mitigate this threat, if possible, thisvulnerability would be prevented, if theprogramming language that was used to programthe software did not use pointers. Anothermitigation suggestion is to check to see if thepointers are referenced correctly prior to theiruse [14].',
            references:[{name:'Null Dereference', link:'https://www.owasp.org/index.php/Null_Dereference'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'In the following code, the programmer assumes that the system always has a property named "cmd" defined. If an attacker can control the program\'s environment so that "cmd" is not defined, the program throws a null pointer exception when it attempts to call the trim() method.',
                    code: 'String cmd = System.getProperty("cmd"); cmd = cmd.trim();'
                },
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'Null-pointer dereference issues can occur through a number of flaws, including race conditions and simple programming omissions. While there are no complete fixes aside from contentious programming, the following steps will go a long way to ensure that null-pointer dereferences do not occur.\n' +
                        '\n' +
                        'Before using a pointer, ensure that it is not equal to NULL:',
                    code: 'if (pointer1 != NULL) {\n' +
                        '  /* make use of pointer1 */\n' +
                        '  /* ... */\n' +
                        '}'
                },
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'When freeing pointers, ensure they are not set to NULL, and be sure to set them to NULL once they are freed:',
                    postText: 'if (pointer1 != NULL) {\n' +
                        '  free(pointer1);\n' +
                        '  pointer1 = NULL;\n' +
                        '}',
                    code: 'If you are working with a multi-threaded or otherwise asynchronous environment, ensure that proper locking APIs are used to lock before the if statement; and unlock when it has finished.\n' +
                        '\n'
                }
            ]
        });});

    flow.rule('Logging Practices',[[Element, 'el','(el.element.attributes.type == "tm.Store" && isTrue(el.element.isALogStore))  ||(el.element.attributes.type == "tm.Process"  && isTrue(el.element.isALog)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.isALogMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch"&& isTrue(el.element.isALogSmartPhone)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.isALogLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.isALogTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.isALogElectrocardiogram)) ||(el.element.attributes.type == "tm.Pacemaker"&& isTrue(el.element.isALogPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.5',
            title:'Logging Practices',
            type:'Repudiation',
            status:'Open',
            severity:'Low',
            description:'Declare Logger Object as Static and Final:It is good programming practice to share a singlelogger object between all of the instances of aparticular class and to use the same logger for theduration of the program.Don\'t Use Multiple Loggers:It is a poor logging practice to use multipleloggers rather than logging levels in a single class.Good logging practice dictates the use of a singlelogger that supports different logging levels foreach class.Don\'t Use System Output Stream:Using System.out or System.err rather than adedicated logging facility makes it difficult tomonitor the behavior of the program. It can alsocause log messages accidentally returned to theend users, revealing internal information toattackers. While most programmers go on tolearn many nuances and subtleties about Java, asurprising number hang on to this first lesson andnever give up on writing messages to standardoutput using System.out.println().The problem is that writing directly to standardoutput or standard error is often used as anunstructured form of logging. Structured loggingfacilities provide features like logging levels,uniform formatting, a logger identifier,timestamps, and, perhaps most critically, theability to direct the log messages to the rightplace. When the use of system output streams isjumbled together with the code that uses loggersproperly, the result is often a well-kept log that ismissing critical information. In addition, usingsystem output streams can also cause logmessages accidentally returned to end users,revealing application internal information toattackers.Developers widely accept the need for structuredlogging, but many continue to use system outputstreams in their \"pre-production\" development.If the code you are reviewing is past the initialphases of development, use of System.out orSystem.err may indicate an oversight in the moveto a structured logging system.',
            mitigation:'To mitigate this threat the logging system shouldbe centralized to the program and give differentlevels of detail, and log/display all securitysuccesses or failures. [17]',
            references:[{name:'Poor Logging Practice', link:'https://www.owasp.org/index.php/Poor_Logging_Practice'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'Logger Not Declared Static Final\n' +
                        'Loggers should be declared to be static and final.\n' +
                        '\n' +
                        'It is good programming practice to share a single logger object between all of the instances of a particular class and to use the same logger for the duration of the program.\n' +
                        '\n' +
                        'The following statement errantly declares a non-static logger.',
                    code: 'private final Logger logger =     \n' +
                        '\t\t\t\tLogger.getLogger(MyClass.class);'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'It is a poor logging practice to use multiple loggers rather than logging levels in a single class.\n' +
                        '\n' +
                        'Good logging practice dictates the use of a single logger that supports different logging levels for each class.\n' +
                        '\n' +
                        'The following code errantly declares multiple loggers.',
                    code: '\tpublic class MyClass {\n' +
                        '\t  private final static Logger good =     \n' +
                        '\t\t\t\tLogger.getLogger(MyClass.class);\n' +
                        '\t  private final static Logger bad =     \n' +
                        '\t\t\t\tLogger.getLogger(MyClass.class);\n' +
                        '\t  private final static Logger ugly =     \n' +
                        '\t\t\t\tLogger.getLogger(MyClass.class);\n' +
                        '\t  ...\n' +
                        '\t}'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'Use of a System Output Stream\n' +
                        'Using System.out or System.err rather than a dedicated logging facility makes it difficult to monitor the behavior of the program. It can also cause log messages accidentally returned to the end users, revealing internal information to attackers.\n' +
                        '\n' +
                        'The first Java program that a developer learns to write often looks like this:',
                    postText: 'While most programmers go on to learn many nuances and subtleties about Java, a surprising number hang on to this first lesson and never give up on writing messages to standard output using System.out.println().\n' +
                        '\n' +
                        'The problem is that writing directly to standard output or standard error is often used as an unstructured form of logging. Structured logging facilities provide features like logging levels, uniform formatting, a logger identifier, timestamps, and, perhaps most critically, the ability to direct the log messages to the right place. When the use of system output streams is jumbled together with the code that uses loggers properly, the result is often a well-kept log that is missing critical information. In addition, using system output streams can also cause log messages accidentally returned to end users, revealing application internal information to attackers.\n' +
                        '\n' +
                        'Developers widely accept the need for structured logging, but many continue to use system output streams in their "pre-production" development. If the code you are reviewing is past the initial phases of development, use of System.out or System.err may indicate an oversight in the move to a structured logging system.',
                    code: '\tpublic class MyClass \n' +
                        '\t  public static void main(String[] args) {\n' +
                        '\t\tSystem.out.println("hello world");\n' +
                        '\t  }\n' +
                        '\t}'
                }
            ]
        });});

    flow.rule('Unreleased Resource',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.usesExternalResourcesProcess)&& isTrue(el.element.usesResourcesDirectlyProcess))|| (el.element.attributes.type == "tm.Store"  && isTrue(el.element.usesExternalResourcesStore)&& isTrue(el.element.usesResourcesDirectlyStore))|| (el.element.attributes.type =="tm.MobilePhone" && isTrue(el.element.usesExternalResourcesMobilePhone) && isTrue(el.element.usesResourcesDirectlyMobilePhone)) || (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.usesExternalResourcesSmartWatch) && isTrue(el.element.usesResourcesDirectlySmartWatch)) || (el.element.attributes.type =="tm.Laptop" && isTrue(el.element.usesExternalResourcesLaptop)&& isTrue(el.element.usesResourcesDirectlyLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.usesExternalResourcesTablet)&& isTrue(el.element.usesResourcesDirectlyTablet))|| (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.usesExternalResourcesElectrcoardiogram) && isTrue(el.element.usesResourcesDirectlyElectrocardiogram)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.usesExternalResourcesPacemaker) && isTrue(el.element.usesResourcesDirectlyPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.6',
            title:'Unreleased Resource',
            type:'Denial of service',
            status:'Open',
            severity:'Medium',
            description:'Most unreleased resource issues result in generalsoftware reliability problems, but if an attacker canintentionally trigger a resource leak, the attackermight be able to launch a denial of service attack bydepleting the resource pool.Resource leaks have at least two common causes:Error conditions and other exceptionalcircumstances.Confusion over which part of the program isresponsible for releasing the resource.',
            mitigation:'To mitigate this threat, the programming languageused to program the desired program, should notallow this threat to occur. Another suggestion is tofree all resources that have been allocated and beconsistent in terms of how memory is allocated andde-allocated. To furthermore mitigate this threat, asuggestion is to release all the member componentsof a given object [27].',
            references:[{name:'CWE-404: Improper Resource Shutdown or Release', link:'https://cwe.mitre.org/data/definitions/404.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following method never closes the file handle it opens. The Finalize() method for StreamReader eventually calls Close(), but there is no guarantee as to how long it will take before the Finalize() method is invoked. In fact, there is no guarantee that Finalize() will ever be invoked. In a busy environment, this can result in the VM using up all of its available file handles.',
                    code: 'private void processFile(string fName) {\n' +
                        'StreamWriter sw = new StreamWriter(fName);\n' +
                        'string line;\n' +
                        'while ((line = sr.ReadLine()) != null){\n' +
                        'processLine(line);\n' +
                        '}\n' +
                        '}'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'This code attempts to open a connection to a database and catches any exceptions that may occur.',
                    postText: 'If an exception occurs after establishing the database connection and before the same connection closes, the pool of database connections may become exhausted. If the number of available connections is exceeded, other users cannot access this resource, effectively denying access to the application.',
                    code: 'try {\n' +
                        'Connection con = DriverManager.getConnection(some_connection_string);\n' +
                        '}\n' +
                        'catch ( Exception e ) {\n' +
                        'log( e );\n' +
                        '}'
                },
                {
                    language: {name: 'C#', highlightAlias: 'csharp'},
                    preText: 'Under normal conditions the following C# code executes a database query, processes the results returned by the database, and closes the allocated SqlConnection object. But if an exception occurs while executing the SQL or processing the results, the SqlConnection object is not closed. If this happens often enough, the database will run out of available cursors and not be able to execute any more SQL queries.',
                    code: '...\n' +
                        'SqlConnection conn = new SqlConnection(connString);\n' +
                        'SqlCommand cmd = new SqlCommand(queryString);\n' +
                        'cmd.Connection = conn;\n' +
                        'conn.Open();\n' +
                        'SqlDataReader rdr = cmd.ExecuteReader();\n' +
                        'HarvestResults(rdr);\n' +
                        'conn.Connection.Close();\n' +
                        '...'
                },
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following C function does not close the file handle it opens if an error occurs. If the process is long-lived, the process can run out of file handles.',
                    code: 'int decodeFile(char* fName) {\n' +
                        'char buf[BUF_SZ];\n' +
                        'FILE* f = fopen(fName, "r");\n' +
                        'if (!f) {\n' +
                        'printf("cannot open %s\\n", fName);\n' +
                        'return DECODE_FAIL;\n' +
                        '}\n' +
                        'else {\n' +
                        'while (fgets(buf, BUF_SZ, f)) {\n' +
                        'if (!checkChecksum(buf)) {\n' +
                        'return DECODE_FAIL;\n' +
                        '}\n' +
                        'else {\n' +
                        'decodeBlock(buf);\n' +
                        '}\n' +
                        '}\n' +
                        '}\n' +
                        'fclose(f);\n' +
                        'return DECODE_SUCCESS;\n' +
                        '}'
                },
                {
                    language: {name: 'C++', highlightAlias: 'cpp'},
                    preText: 'In this example, the program does not use matching functions such as malloc/free, new/delete, and new[]/delete[] to allocate/deallocate the resource.',
                    code: 'class A {\n' +
                        'void foo();\n' +
                        '};\n' +
                        'void A::foo(){\n' +
                        'int *ptr;\n' +
                        'ptr = (int*)malloc(sizeof(int));\n' +
                        'delete ptr;\n' +
                        '}'
                },
                {
                    language: {name: 'C++', highlightAlias: 'cpp'},
                    preText: 'In this example, the program calls the delete[] function on non-heap memory.',
                    code: 'class A{\n' +
                        'void foo(bool);\n' +
                        '};\n' +
                        'void A::foo(bool heap) {\n' +
                        'int localArray[2] = {\n' +
                        '11,22\n' +
                        '};\n' +
                        'int *p = localArray;\n' +
                        'if (heap){\n' +
                        'p = new int[2];\n' +
                        '}\n' +
                        'delete[] p;\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Use of Obsolete Methods',[[Element, 'el','el.element.attributes.type == "tm.Store"  ||el.element.attributes.type == "tm.Process" ||(el.element.attributes.type == "tm.SmartWatch")|| (el.element.attributes.type =="tm.PaceMaker") || (el.element.attributes.type== "tm.Electrocardiogram") ||(el.element.attributes.type =="tm.MobilePhone") ||(el.element.attributes.type == "tm.Laptop") ||(el.element.attributes.type == "tm.Tablet")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.7',
            title:'Use of Obsolete Methods',
            type:'Denial of service',
            status:'Open',
            severity:'Medium',
            description:'The use of deprecated or obsolete functions mayindicate neglected code.As programming languages evolve, functionsoccasionally become obsolete due to:Advances in the languageImproved understanding of how operations shouldbe performed effectively and securelyChanges in the conventions that govern certainoperationsFunctions that are removed are usually replaced bynewer counterparts that perform the same task insome different and hopefully improved way.Refer to the documentation for this function inorder to determine why it is deprecated or obsoleteand to learn about alternative ways to achieve thesame functionality. The remainder of this textdiscusses general problems that stem from the useof deprecated or obsolete functions.',
            mitigation:'To mitigate this threat, the documentation for theprogram should be referred to, to determine thereason it is deprecated and to determinealternatives to using those methods, which maypose not only a function concern, but also a securityconcern. [26]',
            references:[{name:'CWE-477: Use of Obsolete Function', link:'https://cwe.mitre.org/data/definitions/477.html'}],
            examples:[
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following code uses the deprecated function getpw() to verify that a plaintext password matches a user\'s encrypted password. If the password is valid, the function sets result to 1; otherwise it is set to 0.',
                    postText: 'Although the code often behaves correctly, using the getpw() function can be problematic from a security standpoint, because it can overflow the buffer passed to its second parameter. Because of this vulnerability, getpw() has been supplanted by getpwuid(), which performs the same lookup as getpw() but returns a pointer to a statically-allocated structure to mitigate the risk. Not all functions are deprecated or replaced because they pose a security risk. However, the presence of an obsolete function often indicates that the surrounding code has been neglected and may be in a state of disrepair. Software security has not been a priority, or even a consideration, for very long. If the program uses deprecated or obsolete functions, it raises the probability that there are security problems lurking nearby.',
                    code: '...\n' +
                        'getpw(uid, pwdline);\n' +
                        'for (i=0; i<3; i++){\n' +
                        'cryptpw=strtok(pwdline, ":");\n' +
                        'pwdline=0;\n' +
                        '}\n' +
                        'result = strcmp(crypt(plainpw,cryptpw), cryptpw) == 0;\n' +
                        '...'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'In the following code, the programmer assumes that the system always has a property named "cmd" defined. If an attacker can control the program\'s environment so that "cmd" is not defined, the program throws a null pointer exception when it attempts to call the "Trim()" method.',
                    code: 'String cmd = null;\n' +
                        '...\n' +
                        'cmd = Environment.GetEnvironmentVariable("cmd");\n' +
                        'cmd = cmd.Trim();'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following code constructs a string object from an array of bytes and a value that specifies the top 8 bits of each 16-bit Unicode character.',
                    postText: 'In this example, the constructor may not correctly convert bytes to characters depending upon which charset is used to encode the string represented by nameBytes. Due to the evolution of the charsets used to encode strings, this constructor was deprecated and replaced by a constructor that accepts as one of its parameters the name of the charset used to encode the bytes for conversion.',
                    code: '...\n' +
                        'String name = new String(nameBytes, highByte);\n' +
                        '...'
                }
            ]
        });});

    flow.rule('Sensitive Parameters in URL',[[Element, 'el','el.element.attributes.type == "tm.Process"  && isTrue(el.element.isAWebApplication)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '3.1',
            title:'Sensitive Parameters in URL',
            type:'Information disclosure',
            status:'Open',
            severity:'Medium',
            description:'Information exposure through query strings in URLis when sensitive data is passed to parameters inthe URL. This allows attackers to obtain sensitivedata such as usernames, passwords, tokens (authX),database details, and any other potentially sensitivedata. Simply using HTTPS does not resolve thisvulnerability. A very common example is in GETrequests.',
            mitigation:'To mitigate this threat, it is recommended to use aPOST method, as those parameters that are passedin through the URL are not saved, and thereforecannot be exposed. [28]',
            references:[{name:'CWE-598: Information Exposure Through Query Strings in GET Request', link:'https://cwe.mitre.org/data/definitions/598.html'}]});});

    flow.rule('Improper Certificate Validation',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.validatesCertProcess)) ||(el.element.attributes.type == "tm.Store" && isFalse(el.element.validatesCertStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '3.2',
            title:'Improper Certificate Validation',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'The software does not validate, orincorrectly validates, a certificate.[35]',
            mitigation:'Certificates should be carefully managedand check to assure that data areencrypted with the intended owner\'spublic key.If certificate pinning is being used, ensurethat all relevant properties of thecertificate are fully validated before thecertificate is pinned, including thehostname.[35]',
            references:[{name:'CWE-295: Improper Certificate Validation', link:'https://cwe.mitre.org/data/definitions/295.html'}]});});

    flow.rule('Insufficient TLS Protection',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Flow" && isFalse(el.element.usesTLS))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '3.3',
            title:'Insufficient TLS Protection',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Sensitive data must be protected when it istransmitted through the network. Such data caninclude user credentials and credit cards. As a ruleof thumb, if data must be protected when it isstored, it must be protected also duringtransmission.HTTP is a clear-text protocol and it is normallysecured via an SSL/TLS tunnel, resulting in HTTPStraffic. The use of this protocol ensures not onlyconfidentiality, but also authentication. Servers areauthenticated using digital certificates and it is alsopossible to use client certificate for mutualauthentication.Even if high grade ciphers are today supported andnormally used, some misconfiguration in the servercan be used to force the use of a weak cipher - or atworst no encryption - permitting to an attacker togain access to the supposed secure communicationchannel. Other misconfiguration can be used for aDenial of Service attack.See:https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)for more information',
            mitigation:'To mitigate this threat, web servers that providehttps services should have their configurationchecked. As well, the validity of an SSL certificateshould be checked from a client and server point ofview. These would be checked using a variety oftools which are found on the following website:https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)  [31]',
            references:[{name:'Testing for Weak SSL/TLS Ciphers Insufficient Transport Layer Protection (OTG-CRYPST-001)', link:'https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)'}]});});

    flow.rule('Hard-coded Cryptographic Key',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.isEncryptedMobilePhone))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.isEncryptedActor)) ||(el.element.attributes.type == "tm.Flow"  && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm. SmartWatch"&& isTrue(el.element.isEncryptedSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.isEncryptedLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.isEncryptedTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.isEncryptedElectrocardiogram))||(el.element.attributes.type == "tm.Pacemaker"&& isTrue(el.element.isEncryptedPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '3.4',
            title:'Hard-coded Cryptographic Key',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'The use of a hard-coded cryptographic keytremendously increases the possibility thatencrypted data may be recovered.If hard-coded cryptographic keys are used, it isalmost certain that malicious users will gain accessthrough the account in question.',
            mitigation:'To mitigate against this threat, this practice of hardcoding the cryptographic key should be avoided toavoid exposing the cryptographic key to a potentialadversary for exploitation [32]',
            references:[{name:'CWE-321: Use of Hard-coded Cryptographic Key', link:'https://cwe.mitre.org/data/definitions/321.html'}],
            examples:[
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'Attempt to verify a password using a hardcoded cryptographic Key in C:',
                    postText: 'The cryptographic key is within a hard-coded string value that is compared to the password. It is likely that an attacker will be able to read the key and compromise the system.',
                    code: 'int VerifyAdmin(char *password) {\n' +
                        'if (strcmp(password,"68af404b513073584c4b6f22b6c63e6b")) {\n' +
                        '\n' +
                        'printf("Incorrect Password!\\n");\n' +
                        'return(0);\n' +
                        '}\n' +
                        'printf("Entering Diagnostic Mode...\\n");\n' +
                        'return(1);\n' +
                        '}'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'Attempt to verify a password using a hardcoded cryptographic Key in Java:',
                    postText: 'The cryptographic key is within a hard-coded string value that is compared to the password. It is likely that an attacker will be able to read the key and compromise the system.',
                    code: 'public boolean VerifyAdmin(String password) {\n' +
                        'if (password.equals("68af404b513073584c4b6f22b6c63e6b")) {\n' +
                        'System.out.println("Entering Diagnostic Mode...");\n' +
                        'return true;\n' +
                        '}\n' +
                        'System.out.println("Incorrect Password!");\n' +
                        'return false;'
                },
                {
                    language: {name: 'C#', highlightAlias: 'csharp'},
                    preText:'Attempt to verify a password using a hardcoded cryptographic Key in C#:',
                    postText: 'The cryptographic key is within a hard-coded string value that is compared to the password. It is likely that an attacker will be able to read the key and compromise the system.',
                    code: 'int VerifyAdmin(String password) {\n' +
                        'if (password.Equals("68af404b513073584c4b6f22b6c63e6b")) {\n' +
                        'Console.WriteLine("Entering Diagnostic Mode...");\n' +
                        'return(1);\n' +
                        '}\n' +
                        'Console.WriteLine("Incorrect Password!");\n' +
                        'return(0);\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Faulty Cryptographic Algorithm',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.isEncryptedMobilePhone)&& isTrue(dropDownOptionsCheck("encryptionTypeForMobilePhone", "des, rsa, tripleDes,tripleDes3Key, rc2, rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Process" && isTrue(el.element.isEncryptedProcess) && isTrue(dropDownOptionsCheck("encryptionTypeForProcess", "des, rsa, tripleDes, tripleDes3Key,rc2, rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Actor" && isTrue(el.element.isEncryptedActor) && isTrue(dropDownOptionsCheck("encryptionTypeForActor", "des, rsa, tripleDes, tripleDes3Key, rc2,rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Store" && isTrue(el.element.isEncryptedStore) && isTrue(dropDownOptionsCheck("encryptionTypeForStore", "des, rsa, tripleDes, tripleDes3Key, rc2,rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Flow" && isTrue(el.element.isEncryptedFlow) && isTrue(dropDownOptionsCheck("encryptionTypeForFlow", "des, rsa, tripleDes, tripleDes3Key, rc2,rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.SmartWatch"&& isTrue(el.element.isEncryptedSmartWatch)&& isTrue(dropDownOptionsCheck("encryptionTypeForSmartWatch", "des, rsa, tripleDes,tripleDes3Key, rc2, rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Laptop" && isTrue(el.element.isEncryptedLaptop) && isTrue(dropDownOptionsCheck("encryptionTypeForLaptop", "des, rsa, tripleDes, tripleDes3Key,rc2, rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Tablet" && isTrue(el.element.isEncryptedTablet) && isTrue(dropDownOptionsCheck("encryptionTypeForTablet", "des, rsa, tripleDes, tripleDes3Key, rc2,rc4, 128rc4, desx"))) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.isEncryptedElectrocardiogram)&& isTrue(dropDownOptionsCheck("encryptionTypeForElectrocardiogram", "des, rsa, tripleDes,tripleDes3Key, rc2, rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Pacemaker"&& isTrue(el.element.isEncryptedPacemaker) && isTrue(dropDownOptionsCheck("encryptionTypeForStore", "des, rsa, tripleDes, tripleDes3Key, rc2,rc4, 128rc4, desx")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '3.5',
            title:'Faulty Cryptographic Algorithm',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Attempting to create non-standard and non-testedalgorithms, using weak algorithms, or applyingalgorithms incorrectly will pose a high weakness todata that is meant to be secure.',
            mitigation:'To mitigate this threat, a stronger cryptographicalgorithm that is widely known to be secure shouldbe used. Currently, AES is one of the most secureencryption algorithms and is recommended to beused.  [33] [34]Environment (Platform Vulnerabilities)',
            references:[{name:'A Study of Encryption Algorithms (RSA, DES, 3DES and AES) for Information Security', link:'https://pdfs.semanticscholar.org/187d/26258dc57d794ce4badb094e64cf8d3f7d88.pdf '},{name:'Using a broken or risky cryptographic algorithm', link:'https://www.owasp.org/index.php/Using_a_broken_or_risky_cryptographic_algorithm'}],
            examples:[
                {
                    language: {name: 'C++', highlightAlias: 'cpp'},
                    code: 'EVP_des_ecb();'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    code: 'Cipher des=Cipher.getInstance("DES...);\n' +
                        'des.initEncrypt(key2);'
                }
            ]
        });});

    flow.rule('Insecure Transport',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Flow" && isFalse(el.element.usesTLS))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '4.1',
            title:'Insecure Transport',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'The application configuration should ensure thatSSL is used for all access-controlled pages.If an application uses SSL to guarantee confidentialcommunication with client browsers, theapplication configuration should make it impossibleto view any access-controlled page without SSL.However, it is not an uncommon problem that theconfiguration of the application fails to enforce theuse of SSL on pages that contain sensitive data.There are three common ways for SSL to bebypassed:A user manually enters the URL and types \"HTTP\"rather than \"HTTPS\".Attackers intentionally send a user to an insecureURL.A programmer erroneously creates a relative link toa page in the application, failing to switch fromHTTP to HTTPS. (This is particularly easy to do whenthe link moves between public and secured areason a web site.)',
            mitigation:'The first and foremost control that needs to beapplied is to check for a lack of transportencryption. This can be done by:Reviewing network traffic of the device, itsmobile application and any cloud connections todetermine if any information is passed in cleartextReviewing the use of SSL or TLS to ensure it is up todate and properly implementedReviewing the use of any encryption protocols toensure they are recommended and acceptedIn order to ensure enough transport encryption:Ensuring data is encrypted using protocols such asSSL and TLS while transiting networks.Ensuring other industry standard encryptiontechniques are utilized to protect data duringtransport if SSL or TLS are not available.Ensuring only accepted encryption standards areused and avoid using proprietary encryptionprotocols.Ensuring the message payload encryptionEnsuring the secure encryption key handshaking.Ensuring received data integrity verification.[4]',
            references:[{name:'Insecure Transport', link:'https://vulncat.fortify.com/en/detail?id=desc.controlflow.cpp.insecure_transport_weak_ssl_protocol#Swift'}]});});

    flow.rule('Path Traversal',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.localAccessProcess) && isFalse(el.element.validatesInputProcess)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.localAccessStore) && isFalse(el.element.validatesInputStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.localAccessMobilePhone) && isFalse(el.element.validatesInputMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.localAccessSmartWatch) && isFalse(el.element.validatesInputSmartWatch)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.localAccessLaptop) && isFalse(el.element.validatesInputLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.localAccessTablet) && isFalse(el.element.validatesInputTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.localAccessElectrocardiogram) && isFalse(el.element.validatesInputElectrocardiogram))|| (el.element.attributes.type == "tm.Pacemaker"&& isTrue(el.element.localAccessPacemaker) && isFalse(el.element.validatesInputPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '4.2',
            title:'Path Traversal',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'Allows attackers to access files that are not intended tobe accessed. The software uses external input toconstruct a pathname that is intended to identify a fileor directory that is located underneath a restrictedparent directory, but the software does not properlyneutralize special elements within the pathname thatcan cause the pathname to resolve to a location that isoutside of the restricted directory. By using specialelements such as \"..\" and \"/\" separators, attackerscan escape outside of the restricted location to accessfiles or directories that are elsewhere on the system.One of the most common special elements is the\"../\" sequence, which in most modern operatingsystems is interpreted as the parent directory of thecurrent location. This is referred to as relative pathtraversal. Path traversal also covers the use of absolutepathnames such as \"/usr/local/bin\", which may alsobe useful in accessing unexpected files. This is referredto as absolute path traversal.[101]',
            mitigation:': Assume all input is malicious. Use an\"accept known good\" input validation strategy, i.e.,use a whitelist of acceptable inputs that strictlyconform to specifications. Reject any input that doesnot strictly conform to specifications or transform itinto something that does. When performing inputvalidation, consider all potentially relevant properties,including length, type of input, the full range ofacceptable values, missing or extra inputs, syntax,consistency across related fields, and conformance tobusiness rules. As an example of business rule logic,\"boat\" may be syntactically valid because it onlycontains alphanumeric characters, but it is not valid ifthe input is only expected to contain colors such as\"red\" or \"blue.\" Do not rely exclusively on lookingfor malicious or malformed inputs (i.e., do not rely on ablacklist). A blacklist is likely to miss at least oneundesirable input, especially if the code\'senvironment changes. This can give attackers enoughroom to bypass the intended validation. However,blacklists can be useful for detecting potential attacksor determining which inputs are so malformed thatthey should be rejected outright.Use a vetted library or framework that does not allowthis weakness to occur or provides constructs thatmake this weakness easier to avoid.Use an application firewall that can detect attacksagainst this weakness. It can be beneficial in cases inwhich the code cannot be fixed (because it iscontrolled by a third party), as an emergencyprevention measure while more comprehensivesoftware assurance measures are applied, or toprovide defense in depth.Run your code using the lowest privileges that arerequired to accomplish the necessary tasks. If possible,create isolated accounts with limited privileges thatare only used for a single task. That way, a successfulattack will not immediately give the attacker access tothe rest of the software or its environment. Forexample, database applications rarely need to run asthe database administrator, especially in day-to-dayoperations.Run the code in a \"jail\" or similar sandboxenvironment that enforces strict boundaries betweenthe process and the operating system. This mayeffectively restrict which files can be accessed in adirectory or which command can be executed by thesoftware. OS-level examples include the Unix chrootjail, AppArmor, and SELinux. In general, managed codemay provide some protection. For example,java.io.FilePermission in the Java SecurityManagerallows the software to specify restrictions on fileoperations.Attack Surface Reduction: Store library, include, andutility files outside of the web document root, ifpossible. Otherwise, store them in a separate directoryand use the web server\'s access control capabilities toprevent attackers from directly requesting them. Onecommon practice is to define a fixed constant in eachcalling program, then check for the existence of theconstant in the library/include file; if the constant doesnot exist, then the file was directly requested, and itcan exit immediately. This significantly reduces thechance of an attacker being able to bypass anyprotection mechanisms that are in the base programbut not in the include files. It will also reduce theattack surface.Ensure that error messages only contain minimaldetails that are useful to the intended audience, andnobody else. The messages need to strike the balancebetween being too cryptic and not being crypticenough. They should not necessarily reveal themethods that were used to determine the error. Suchdetailed information can be used to refine the originalattack to increase the chances of success. In thecontext of path traversal, error messages whichdisclose path information can help attackers craft theappropriate attack strings to move through the filesystem hierarchy.[8]',
            references:[{name:'CWE-22: Improper Limitation of a Pathname to a Restricted Directory (\'Path Traversal\')', link:'http://cwe.mitre.org/data/definitions/22.html'},{name:'CWE-272: Least Privilege Violation', link:'https://cwe.mitre.org/data/definitions/272.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'In the example below, the path to a dictionary file is read from a system property and used to initialize a File object.',
                    postText: 'However, the path is not validated or modified to prevent it from containing relative or absolute path sequences before creating the File object. This allows anyone who can control the system property to determine what file is used. Ideally, the path should be resolved relative to some kind of application or user home directory.',
                    code: 'String filename = System.getProperty("com.domain.application.dictionaryFile");\n' +
                        'File dictionaryFile = new File(filename);'
                }
            ]
        });});

    flow.rule('Exposure of Private Information (Privacy Violation)',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isFalse(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isFalse(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isFalse(el.element.privilegeLevelForMobilePhone)) ||(el.element.attributes.type == "tm.Pacemaker" && isFalse(el.element.privilegeLevelForPacemaker)) ||(el.element.attributes.type == "tm.SmartWatch" && isFalse(el.element.privilegeLevelForSmartWatch)) ||(el.element.attributes.type == "tm.Laptop" && isFalse(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isFalse(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram"&& isFalse(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '4.3',
            title:'Exposure of Private Information (Privacy Violation)',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'The software does not properly prevent private data(such as credit card numbers) from being accessed byactors who either (1) are not explicitly authorized toaccess the data or (2) do not have the implicit consent ofthe people to which the data is related. Mishandlingprivate information, such as customer passwords or SocialSecurity numbers, can compromise user privacy and isoften illegal. An exposure of private information does notnecessarily prevent the software from working properly,and in fact it might be intended by the developer, but itcan still be undesirable (or explicitly prohibited by law) forthe people who are associated with this privateinformation. Some examples of private informationinclude: social security numbers, web surfing history,credit card numbers, bank accounts, personal healthrecords such as medical conditions, insuranceinformation, prescription records, medical histories, testand laboratory results.[9]',
            mitigation:'Separation of Privilege by compartmentalizing the systemto have \"safe\" areas where trust boundaries can beunambiguously drawn. Do not allow sensitive data to gooutside of the trust boundary and always be careful wheninterfacing with a compartment outside of the safe area.Ensure that appropriate compartmentalization is builtinto the system design and that the compartmentalizationserves to allow for and further reinforce privilegeseparation functionality. Architects and designers shouldrely on the principle of least privilege to decide when it isappropriate to use and to drop system privileges.',
            references:[{name:'CWE-359: Exposure of Private Information (\'Privacy Violation\')', link:'https://cwe.mitre.org/data/definitions/359.html'}],
            examples:[
                {
                    preText: 'In 2004, an employee at AOL sold approximately 92 million private customer e-mail addresses to a spammer marketing an offshore gambling web site. In response to such high-profile exploits, the collection and management of private data is becoming increasingly regulated.'
                },
                {
                    language: {name: 'C#', highlightAlias: 'csharp'},
                    preText: 'The following code contains a logging statement that tracks the contents of records added to a database by storing them in a log file. Among other values that are stored, the getPassword() function returns the user-supplied plaintext password associated with the account.',
                    postText: 'The code in the example above logs a plaintext password to the filesystem. Although many developers trust the filesystem as a safe storage location for data, it should not be trusted implicitly, particularly when privacy is a concern.',
                    code: 'pass = GetPassword();\n' +
                        '...\n' +
                        'dbmsLog.WriteLine(id + ":" + pass + ":" + type + ":" + tstamp);'
                },
                {
                    language: {name: 'Markup', highlightAlias: 'markup'},
                    preText: 'This code uses location to determine the user\'s current US State location. First the application must declare that it requires the ACCESS_FINE_LOCATION permission in the application\'s manifest.xml:',
                    postText: 'During execution, a call to getLastLocation() will return a location based on the application\'s location permissions.',
                    code: '<usespermission android:name=\\"android.permission.ACCESS_FINE_LOCATION\\"\\/>'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'In this case the application has permission for the most accurate location possible:',
                    postText: 'While the application needs this information, it does not need to use the ACCESS_FINE_LOCATION permission, as the ACCESS_COARSE_LOCATION permission will be sufficient to identify which US state the user is in.',
                    code: 'locationClient = new LocationClient(this, this, this);\n' +
                        'locationClient.connect();\n' +
                        'Location userCurrLocation;\n' +
                        'userCurrLocation = locationClient.getLastLocation();\n' +
                        'deriveStateFromCoords(userCurrLocation);'
                }
            ]

        });});

    flow.rule('Catch NullPointerException',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess", "objectivec,c#, java, python"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforSmartWatch","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforLaptop","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforTablet","objectivec, c#, java, python"))) || (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforElectrocardiogram","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforPacemaker","objectivec, c#, java, python")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '5.1',
            title:'Catch NullPointerException',
            type:'Denial of service',
            status:'Open',
            severity:'Medium',
            description:'It is generally a bad practice to catch NullPointerException. Programmers typically catchNullPointerException under three circumstances:The program contains a null pointer dereference. Catching the resulting exception waseasier than fixing the underlying problem.The program explicitly throws a NullPointerException to signal an error condition.The code is part of a test harness that supplies unexpected input to the classes under test.This is the only acceptable scenario.[15]',
            mitigation:'Do not extensively rely on catching exceptions (especially for validating user input) tohandle errors. Handling exceptions can decrease the performance of an application.[15]',
            references:[{name:'CWE-395: Use of NullPointerException Catch to Detect NULL Pointer Dereference', link:'https://cwe.mitre.org/data/definitions/395.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following code mistakenly catches a NullPointerException.\n',
                    code: 'try {\n' +
                        'mysteryMethod();\n' +
                        '} catch (NullPointerException npe) {\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Empty Catch Block',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess", "objectivec,c#, java, python"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforSmartWatch","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforLaptop","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforTablet","objectivec, c#, java, python"))) || (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforElectrocardiogram","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforPacemaker","objectivec, c#, java, python")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '5.2',
            title:'Empty Catch Block',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'The software detects a specific error but takes noactions to handle the error.[16]',
            mitigation:'Properly handle each exception. This is therecommended solution. Ensure that all exceptionsare handled in such a way that you can be sure ofthe state of your system at any given moment.If a function returns an error, it is important toeither fix the problem and try again, alert the userthat an error has happened and let the programcontinue, or alert the user and close and cleanupthe program.When testing subject, the software to extensivetesting to discover some of the possible instances ofwhere/how errors or return values are not handled.Consider testing techniques such as ad hoc,equivalence partitioning, robustness and faulttolerance, mutation, and fuzzing.[16]',
            references:[{name:'CWE-390: Detection of Error Condition Without Action', link:'https://cwe.mitre.org/data/definitions/390.html'}],
            examples:[
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following example attempts to allocate memory for a character. After the call to malloc, an if statement is used to check whether the malloc function failed.',
                    postText: 'The conditional successfully detects a NULL return value from malloc indicating a failure, however it does not do anything to handle the problem. Unhandled errors may have unexpected results and may cause the program to crash or terminate.',
                    code: 'foo=malloc(sizeof(char)); //the next line checks to see if malloc failed\n' +
                        'if (foo==NULL) {\n' +
                        '//We do nothing so we just ignore the error.\n' +
                        '}'
                },
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'Instead, the if block should contain statements that either attempt to fix the problem or notify the user that an error has occurred and continue processing or perform some cleanup and gracefully terminate the program. The following example notifies the user that the malloc function did not allocate the required memory resources and returns an error code.',
                    code: 'foo=malloc(sizeof(char)); //the next line checks to see if malloc failed\n' +
                        'if (foo==NULL) {\n' +
                        'printf("Malloc failed to allocate memory resources");\n' +
                        'return -1;\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Missing Error Handling',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.SmartWatch"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type ==  "tm.Electrocardiogram"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "python, java, objectivec, c#, c++, c")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '5.3',
            title:'Missing Error Handling',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'A web application must define a default error pagefor 404 errors, 500 errors, and to catch java.lang.Throwable exceptions prevent attackers frommining information from the applicationcontainer\'s built-in error response. When anattacker explores a web site looking forvulnerabilities, the amount of information that thesite provides is crucial to the eventual success orfailure of any attempted attacks. If the applicationshows the attacker a stack trace, it relinquishesinformation that makes the attacker\'s jobsignificantly easier. For example, a stack trace mightshow the attacker a malformed SQL query string,the type of database being used, and the version ofthe application container. This information enablesthe attacker to target known vulnerabilities in thesecomponents.[18]',
            mitigation:'The application configuration should specify adefault error page in order to guarantee that theapplication will never leak error messages to anattacker. Handling standard HTTP error codes isuseful and user-friendly in addition to being a goodsecurity practice, and a good configuration will alsodefine a last-chance error handler that catches anyexception that could possibly be thrown by theapplication.A specific policy for how to handle errors shouldbe documented, including the types of errors tobe handled and for each, what information isgoing to be reported back to the user, and whatinformation is going to be logged. All developersneed to understand the policy and ensure thattheir code follows it.When errors occur, the site should respond with aspecifically designed result that is helpful to theuser without revealing unnecessary internal details.Certain classes of errors should be logged to helpdetect implementation flaws in the site and/orhacking attempts. Very few sites have any intrusiondetection capabilities in their web application, but itis certainly conceivable that a web application couldtrack repeated failed attempts and generate alerts.[19]',
            references:[{name:'Missing Error Handling', link:'https://www.owasp.org/index.php/Missing_Error_Handling'},{name:'Improper Error Handling', link:'https://www.owasp.org/index.php/Improper_Error_Handling'}],
            examples:[
                {
                    preText: 'An "HTTP 404 - File not found" error tells an attacker that the requested file doesn\'t exist rather than that he doesn\'t have access to the file. This can help the attacker to decide his next step.',
                }
            ]
        });});

    flow.rule('Return Inside Finally Block', {scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.SmartWatch"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type ==  "tm.Electrocardiogram"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "python, java, objectivec, c#, c++, c")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '5.4',
            title:'Return Inside Finally Block',
            type:'Denial of service',
            status:'Open',
            severity:'Low',
            description:'The code has a return statement inside a finallyblock, which will cause any thrown exception in thetry block to be discarded.[20]',
            mitigation:'Do not use a return statement inside the finallyblock. The finally block should have \"cleanup\"code.[20]',
            references:[{name:'CWE-584: Return Inside Finally Block', link:'https://cwe.mitre.org/data/definitions/584.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'In the following code excerpt, the IllegalArgumentException will never be delivered to the caller. The finally block will cause the exception to be discarded.',
                    code: 'try {\n' +
                        '...\n' +
                        'throw IllegalArgumentException();\n' +
                        '}\n' +
                        'finally {\n' +
                        'return r;\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Unchecked Error Condition',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.SmartWatch"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type ==  "tm.Electrocardiogram"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "python, java, objectivec, c#, c++, c")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '5.5',
            title:'Unchecked Error Condition',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'Ignoring exceptions and other error conditions mayallow an attacker to induce unexpected behaviorunnoticed.[21]',
            mitigation:'The choice between a language which has named,or unnamed exceptions needs to be done. Whileunnamed exceptions exacerbate the chance of notproperly dealing with an exception, namedexceptions suffer from the up-call version of theweak base class problem.A language can be used which requires, at compiletime, to catch all serious exceptions. However, onemust make sure to use the most current version ofthe API as new exceptions could be added.Catch all relevant exceptions. This is therecommended solution. Ensure that all exceptionsare handled in such a way that you can be sure ofthe state of your system at any given moment.[21]',
            references:[{name:'CWE-391: Unchecked Error Condition', link:'https://cwe.mitre.org/data/definitions/391.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following code excerpt ignores a rarely-thrown exception from doExchange().',
                    postText: 'If a RareException were to ever be thrown, the program would continue to execute as though nothing unusual had occurred. The program records no evidence indicating the special situation, potentially frustrating any later attempt to explain the program\'s behavior.',
                    code: 'try {\n' +
                        'doExchange();\n' +
                        '}\n' +
                        'catch (RareException e) {\n' +
                        '\n' +
                        '// this can never happen \n' +
                        '}'
                }
            ]
        });});

    flow.rule('Deserialization of Untrusted Data',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.isEncryptedProcess) && isFalse(el.element.validatesInputProcess)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore) && isFalse(el.element.validatesInputStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.isEncryptedMobilePhone) && isFalse(el.element.validatesInputMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.isEncryptedSmartWatch) && isFalse(el.element.validatesInputSmartWatch)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.isEncryptedLaptop) && isFalse(el.element.validatesInputLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.isEncryptedTablet) && isFalse(el.element.validatesInputTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.isEncryptedElectrocardiogram) && isFalse(el.element.validatesInputElectrocardiogram))|| (el.element.attributes.type == "tm.Pacemaker"&& isTrue(el.element.isEncryptedPacemaker) && isFalse(el.element.validatesInputPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.1',
            title:'Deserialization of Untrusted Data',
            type:'Denial of service',
            status:'Open',
            severity:'Medium',
            description:'The application deserializes untrusted datawithout sufficiently verifying that theresulting data will be valid. It is oftenconvenient to serialize objects forcommunication or to save them for lateruse. However, deserialized data or code canoften be modified without using theprovided accessor functions if it does notuse cryptography to protect itself.[22]',
            mitigation:'If available, use the signing/sealingfeatures of the programming language toassure that deserialized data has not beentainted. For example, a hash-basedmessage authentication code (HMAC)could be used to ensure that data has notbeen modified.When deserializing data, populate a newobject rather than just deserializing. Theresult is that the data flows through safeinput validation and that the functions aresafe.Explicitly define a final object() to preventdeserialization.Make fields transient to protect them fromdeserialization.An attempt to serialize and thendeserialize a class containing transientfields will result in NULLs where thetransient data should be.Avoid having unnecessary types orgadgets available that can be leveragedfor malicious ends. This limits thepotential for unintended or unauthorizedtypes and gadgets to be leveraged by theattacker. Whitelist acceptable classes.NOTE: This is alone is not a sufficientmitigation.[22]',
            references:[{name:'CWE-502: Deserialization of Untrusted Data', link:'https://cwe.mitre.org/data/definitions/502.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'This code snippet deserializes an object from a file and uses it as a UI button:',
                    postText: 'This code does not attempt to verify the source or contents of the file before deserializing it. An attacker may be able to replace the intended file with a file that contains arbitrary malicious code which will be executed when the button is pressed.',
                    code: 'try {\n' +
                        'File file = new File("object.obj");\n' +
                        'ObjectInputStream in = new ObjectInputStream(new FileInputStream(file));\n' +
                        'javax.swing.JButton button = (javax.swing.JButton) in.readObject();\n' +
                        'in.close();\n' +
                        '}'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'To mitigate this, explicitly define final readObject() to prevent deserialization. An example of this is:',
                    code: 'private final void readObject(ObjectInputStream in) throws java.io.IOException {\n' +
                        'throw new java.io.IOException("Cannot be deserialized"); }'
                },
                {
                    language: {name: 'Python', highlightAlias: 'python'},
                    preText: 'In Python, the Pickle library handles the serialization and deserialization processes. The code below receives and parses data, and afterwards tries to authenticate a user based on validating a token.',
                    postText: 'Unfortunately, the code does not verify that the incoming data is legitimate. An attacker can construct a illegitimate, serialized object "AuthToken" that instantiates one of Python\'s subprocesses to execute arbitrary commands. For instance,the attacker could construct a pickle that leverages Python\'s subprocess module, which spawns new processes and includes a number of arguments for various uses. Since Pickle allows objects to define the process for how they should be unpickled, the attacker can direct the unpickle process to call Popen in the subprocess module and execute /bin/sh.',
                    code: 'try {\n' +
                        'class ExampleProtocol(protocol.Protocol):\n' +
                        'def dataReceived(self, data):\n' +
                        '\n' +
                        '# Code that would be here would parse the incoming data\n' +
                        '# After receiving headers, call confirmAuth() to authenticate\n' +
                        '\n' +
                        'def confirmAuth(self, headers):\n' +
                        'try:\n' +
                        'token = cPickle.loads(base64.b64decode(headers[\'AuthToken\']))\n' +
                        'if not check_hmac(token[\'signature\'], token[\'data\'], getSecretKey()):\n' +
                        'raise AuthFail\n' +
                        'self.secure_data = token[\'data\']\n' +
                        'except:\n' +
                        'raise AuthFail\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Expression Language Injection',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","jsp, juel, spring"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "jsp, juel, spring"))) || (el.element.attributes.type == "tm.SmartWatch"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "jsp, juel, spring"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","jsp, juel, spring"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "jsp, juel, spring"))) || (el.element.attributes.type ==  "tm.Electrocardiogram"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "jsp, juel, spring"))) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "jsp, juel, spring")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.2',
            title:'Expression Language Injection',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'Server-side code injection vulnerabilities arise whenan application incorporates user-controllable datainto a string that is dynamically evaluated by a codeinterpreter. If the user data is not strictly validated,an attacker can use crafted input to modify thecode to be executed and inject arbitrary code thatwill be executed by the server. Server-side codeinjection vulnerabilities are usually very serious andlead to complete compromise of the application\'sdata and functionality, and often of the server thatis hosting the application. It may also be possible touse the server as a platform for further attacksagainst other systems.[23]',
            mitigation:'Whenever possible, applications should avoidincorporating user-controllable data intodynamically evaluated code. In almost everysituation, there are safer alternative methods ofimplementing application functions, which cannotbe manipulated to inject arbitrary code into theserver\'s processing.If it is considered unavoidable to incorporate user-supplied data into dynamically evaluated code, thenthe data should be strictly validated. Ideally, awhitelist of specific accepted values should be used.Otherwise, only short alphanumeric strings shouldbe accepted. Input containing any other data,including any conceivable code metacharacters,should be rejected.[23]',
            references:[{name:'Expression Language injection', link:'https://portswigger.net/kb/issues/00100f20_expression-language-injection'}]});});

    flow.rule('Form Action Hijacking',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","html"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "html"))) || (el.element.attributes.type == "tm.SmartWatch"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "html"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","html"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "html"))) || (el.element.attributes.type ==  "tm.Electrocardiogram"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "html"))) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "html")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.3',
            title:'Form Action Hijacking',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'Form action hijacking vulnerabilities arise when anapplication places user-supplied input into theaction URL of an HTML form. An attacker can usethis vulnerability to construct a URL that, if visitedby another application user, will modify the actionURL of a form to point to the attacker\'s server. If auser submits the form then its contents, includingany input from the victim user, will be delivereddirectly to the attacker. Even if the user doesn\'tenter any sensitive information, the form may stilldeliver a valid CSRF token to the attacker, enablingthem to perform CSRF attacks. In some cases, webbrowsers may help exacerbate this issue byautocompleting forms with previously entered userinput.[24]',
            mitigation:'Consider hard-coding the form action URL orimplementing a whitelist of allowed values.[24]',
            references:[{name:'Form action hijacking (reflected)', link:'https://portswigger.net/kb/issues/00501500_form-action-hijacking-reflected'}]});});

    flow.rule('Improper Input Validation',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.validatesInputProcess)) ||(el.element.attributes.type == "tm.Store" && isFalse(el.element.validatesInputStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isFalse(el.element.validatesInputMobilePhone))|| (el.element.attributes.type == "tm.SmartWatch"&& isFalse(el.element.validatesInputSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isFalse(el.element.validatesInputLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isFalse(el.element.validatesInputTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isFalse(el.element.validatesInputElectrocardiogram))|| (el.element.attributes.type == "tm.Pacemaker"&& isFalse(el.element.validatesInputPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.4',
            title:'Improper Input Validation',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'The product does not validate or incorrectlyvalidates input that can affect the controlflow or data flow of a program. Whensoftware does not validate input properly,an attacker is able to craft the input in aform that is not expected by the rest of theapplication. This will lead to parts of thesystem receiving unintended input, whichmay result in altered control flow, arbitrarycontrol of a resource, or arbitrary codeexecution.[25]',
            mitigation:'Use an input validation framework such asStruts or the OWASP ESAPI ValidationAPI. If you use Struts, be mindful ofStruts Validation ProblemsUnderstand all the potential areas whereuntrusted inputs can enter your software:parameters or arguments, cookies,anything read from the network,environment variables, reverse DNSlookups, query results, request headers,URL components, e-mail, files, filenames,databases, and any external systems thatprovide data to the application.Remember that such inputs may beobtained indirectly through API calls.Assume all input is malicious. Use an\"accept known good\" input validationstrategy, i.e., use a whitelist of acceptableinputs that strictly conform tospecifications. Reject any input that doesnot strictly conform to specifications ortransform it into something that does.When performing input validation,consider all potentially relevantproperties, including length, type of input,the full range of acceptable values,missing or extra inputs, syntax,consistency across related fields, andconformance to business rules. As anexample of business rule logic, \"boat\"may be syntactically valid because it onlycontains alphanumeric characters, but it isnot valid if the input is only expected tocontain colors such as \"red\" or \"blue.\"Do not rely exclusively on looking formalicious or malformed inputs (i.e., donot rely on a blacklist). A blacklist is likelyto miss at least one undesirable input,especially if the code\'s environmentchanges. This can give attackers enoughroom to bypass the intended validation.However, blacklists can be useful fordetecting potential attacks or determiningwhich inputs are so malformed that theyshould be rejected outright.For any security checks that areperformed on the client side, ensure thatthese checks are duplicated on the serverside, in order to avoid client-sideenforcement of server-side securityAttackers can bypass the client-sidechecks by modifying values after thechecks have been performed, or bychanging the client to remove the client-side checks entirely. Then, these modifiedvalues would be submitted to the server.Use dynamic tools and techniques thatinteract with the software using large testsuites with many diverse inputs, such asfuzz testing (fuzzing), robustness testing,and fault injection.Use tools and techniques that requiremanual (human) analysis, such aspenetration testing, threat modeling, andinteractive tools that allow the tester torecord and modify an active session[25]',
            references:[{name:'CWE-20: Improper Input Validation', link:'https://cwe.mitre.org/data/definitions/20.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'This example demonstrates a shopping interaction in which the user is free to specify the quantity of items to be purchased and a total is calculated.',
                    postText: 'The user has no control over the price variable, however the code does not prevent a negative value from being specified for quantity. If an attacker were to provide a negative value, then the user would have their account credited instead of debited.',
                    code: '...\n' +
                        'public static final double price = 20.00;\n' +
                        'int quantity = currentUser.getAttribute("quantity");\n' +
                        'double total = price * quantity;\n' +
                        'chargeUser(total);\n' +
                        '...'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following example takes a user-supplied value to allocate an array of objects and then operates on the array.',
                    postText: 'This example attempts to build a list from a user-specified value, and even checks to ensure a non-negative value is supplied. If, however, a 0 value is provided, the code will build an array of size 0 and then try to store a new Widget in the first location, causing an exception to be thrown.',
                    code: 'private void buildList ( int untrustedListSize ){\n' +
                        'if ( 0 > untrustedListSize ){\n' +
                        'die("Negative value supplied for list size, die evil hacker!");\n' +
                        '}\n' +
                        'Widget[] list = new Widget [ untrustedListSize ];\n' +
                        'list[0] = new Widget();\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Missing XML Validation',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.isEncryptedProcess) && isTrue(el.element.validateXML))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.5',
            title:'Missing XML Validation',
            type:'Elevation of privilege',
            status:'Open',
            severity:'High',
            description:'The software accepts XML from anuntrusted source but does not validatethe XML against the proper schema. Mostsuccessful attacks begin with a violationof the programmer\'s assumptions. Byaccepting an XML document withoutvalidating it against a DTD or XMLschema, the programmer leaves a dooropen for attackers to provide unexpected,unreasonable, or malicious input.[36]',
            mitigation:'Always validate XML input against aknown XML Schema or DTD.It is not possible for an XML parser tovalidate all aspects of a document\'scontent because a parser cannotunderstand the complete semantics ofthe data. However, a parser can do acomplete and thorough job of checkingthe document\'s structure and thereforeguarantee to the code that processes thedocument that the content is well-formed.A XML validator should be used to checkto check the schema of the XML file. Asuggested validator that can be used isfound at this website :https://www.freeformatter.com/xml-validator-xsd.html[36]',
            references:[{name:'CWE-112: Missing XML Validation', link:'https://cwe.mitre.org/data/definitions/112.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following code loads and parses an XML file.',
                    postText: 'The XML file is loaded without validating it against a known XML Schema or DTD.',
                    code: '// Read DOM \n' +
                        'try {\n' +
                        '...\n' +
                        'DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();\n' +
                        'factory.setValidating( false );\n' +
                        '....\n' +
                        'c_dom = factory.newDocumentBuilder().parse( xmlFile );\n' +
                        '} catch(Exception ex) {\n' +
                        '...\n' +
                        '}'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following code creates a DocumentBuilder object to be used in building an XML document.',
                    postText: 'The DocumentBuilder object does not validate an XML document against a schema, making it possible to create an invalid XML document.',
                    code: 'DocumentBuilderFactory builderFactory = DocumentBuilderFactory.newInstance();\n' +
                        'builderFactory.setNamespaceAware(true);\n' +
                        'DocumentBuilder builder = builderFactory.newDocumentBuilder();'
                }
            ]
        });});

    flow.rule('Overly Permissive Regular Expression',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.userInputProcess)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.userInputStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.userInputMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.userInputSmartWatch)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.userInputTablet)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.userInputLaptop)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.userInputElectrocardiogram)) ||(el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.userInputPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.6',
            title:'Overly Permissive Regular Expression',
            type:'Elevation of privilege',
            status:'Open',
            severity:'High',
            description:'The product uses a regular expression that does notsufficiently restrict the set of allowed values. [38]',
            mitigation:'To mitigate this threat, where possible, ensure thatthe regular expressions does a check to see wherethe start and end string patterns are. As well thereshould be a restriction to limit the number ofcharacters in a given string that the regularexpression will check.[38] [39]',
            references:[{name:'CWE-625: Permissive Regular Expression', link:'https://cwe.mitre.org/data/definitions/625.html'},{name:'Overly Permissive Regular Expression', link:'https://www.owasp.org/index.php/Overly_Permissive_Regular_Expression'}],
            examples:[
                {
                    language: {name: 'Perl', highlightAlias: 'perl'},
                    preText: 'The following example demonstrates the weakness.',
                    postText: 'An attacker could provide an argument such as: "; ls -l ; echo 123-456" This would pass the check, since "123-456" is sufficient to match the "\\d+-\\d+" portion of the regular expression.',
                    code: '$phone = GetPhoneNumber();\n' +
                        'if ($phone =~ /\\d+-\\d+/) {\n' +
                        '\n' +
                        '# looks like it only has hyphens and digits \n' +
                        'system("lookup-phone $phone");\n' +
                        '}\n' +
                        'else {\n' +
                        'error("malformed number!");\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Process Control',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.thirdPartyProcess)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.thirdPartyStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.7',
            title:'Process Control',
            type:'Denial of service',
            status:'Open',
            severity:'Medium',
            description:'Executing commands or loading librariesfrom an untrusted source or in anuntrusted environment can cause anapplication to execute maliciouscommands (and payloads) on behalf ofan attacker. Process controlvulnerabilities take two forms: Anattacker can change the command thatthe program executes by explicitlycontrolling what the command is. Anattacker can change the environment inwhich the command executes byimplicitly controlling what the commandmeans. Process control vulnerabilities ofthe first type occur when either dataenters the application from an untrustedsource and the data is used as part of astring representing a command that isexecuted by the application. By executingthe command, the application gives anattacker a privilege or capability that theattacker would not otherwise have.[37]',
            mitigation:'Libraries that are loaded should be wellunderstood and come from a trustedsource. The application can execute codecontained in the native libraries, whichoften contain calls that are susceptible toother security problems, such as bufferoverflows or command injection. Allnative libraries should be validated todetermine if the application requires theuse of the library. It is very difficult todetermine what these native libraries do,and the potential for malicious code ishigh. In addition, the potential for aninadvertent mistake in these nativelibraries is also high, as many are writtenin C or C++ and may be susceptible tobuffer overflow or race conditionproblems. To help prevent buffer overflowattacks, validate all input to native callsfor content and length. If the nativelibrary does not come from a trustedsource, review the source code of thelibrary. The library should be built fromthe reviewed source before using it.[37]',
            references:[{name:'CWE-114: Process Control', link:'https://cwe.mitre.org/data/definitions/114.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following code uses System.loadLibrary() to load code from a native library named library.dll, which is normally found in a standard system directory.',
                    postText: 'The problem here is that System.loadLibrary() accepts a library name, not a path, for the library to be loaded. From the Java 1.4.2 API documentation this function behaves as follows [1]: A file containing native code is loaded from the local file system from a place where library files are conventionally obtained. The details of this process are implementation-dependent. The mapping from a library name to a specific filename is done in a system-specific manner. If an attacker is able to place a malicious copy of library.dll higher in the search order than file the application intends to load, then the application will load the malicious copy instead of the intended file. Because of the nature of the application, it runs with elevated privileges, which means the contents of the attacker\'s library.dll will now be run with elevated privileges, possibly giving them complete control of the system.',
                    code: '...\n' +
                        'System.loadLibrary("library.dll");\n' +
                        '...'
                },
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following code from a privileged application uses a registry entry to determine the directory in which it is installed and loads a library file based on a relative path from the specified directory.',
                    postText: 'The code in this example allows an attacker to load an arbitrary library, from which code will be executed with the elevated privilege of the application, by modifying a registry key to specify a different path containing a malicious version of INITLIB. Because the program does not validate the value read from the environment, if an attacker can control the value of APPHOME, they can fool the application into running malicious code.',
                    code: '...\n' +
                        'RegQueryValueEx(hkey, "APPHOME",\n' +
                        '0, 0, (BYTE*)home, &size);\n' +
                        'char* lib=(char*)malloc(strlen(home)+strlen(INITLIB));\n' +
                        'if (lib) {\n' +
                        '\n' +
                        'strcpy(lib,home);\n' +
                        'strcat(lib,INITCMD);\n' +
                        'LoadLibrary(lib);\n' +
                        '}\n' +
                        '...'
                },
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following code is from a web-based administration utility that allows users access to an interface through which they can update their profile on the system. The utility makes use of a library named liberty.dll, which is normally found in a standard system directory.',
                    postText: 'The problem is that the program does not specify an absolute path for liberty.dll. If an attacker is able to place a malicious library named liberty.dll higher in the search order than file the application intends to load, then the application will load the malicious copy instead of the intended file. Because of the nature of the application, it runs with elevated privileges, which means the contents of the attacker\'s liberty.dll will now be run with elevated privileges, possibly giving the attacker complete control of the system. The type of attack seen in this example is made possible because of the search order used by LoadLibrary() when an absolute path is not specified. If the current directory is searched before system directories, as was the case up until the most recent versions of Windows, then this type of attack becomes trivial if the attacker can execute the program locally. The search order is operating system version dependent, and is controlled on newer operating systems by the value of the registry key: HKLM\\System\\CurrentControlSet\\Control\\Session Manager\\SafeDllSearchMode',
                    code: 'LoadLibrary("liberty.dll");'
                }
            ]
        });});

    flow.rule('String Termination Error',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","c, c++, assembly"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "c, c++, assembly"))) || (el.element.attributes.type == "tm.SmartWatch"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "c, c++, assembly"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","c, c++, assembly"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "c,c++, assembly"))) || (el.element.attributes.type ==  "tm.Electrocardiogram"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "c, c++, assembly"))) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "c, c++, assembly")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.8',
            title:'String Termination Error',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'Relying on proper string termination may result in a buffer overflow.String termination errors occur when:Data enters a program via a function that does not null terminate itsoutput.The data is passed to a function that requires its input to be nullterminated.[41]',
            mitigation:'Use a language that is not susceptible to these issues. However, be carefulof null byte interaction errors with lower-level constructs that may bewritten in a language that is susceptible.Ensure that all string functions used are understood fully as to how theyappend null characters. Also, be wary of off-by-one errors whenappending nulls to the end of strings.If performance constraints permit, special code can be added thatvalidates null-termination of string buffers, this is a rather naive and error-prone solution.Switch to bounded string manipulation functions. Inspect buffer lengthsinvolved in the buffer overrun trace reported with the defect.Add code that fills buffers with nulls (however, the length of buffers stillneeds to be inspected, to ensure that the non-null-terminated string is notwritten at the physical end of the buffer).Visit the following pages for more information for mitigation strategies forstrings in C and C++:http://www.informit.com/articles/article.aspx?p=2036582&seqNum=4https://www.synopsys.com/blogs/software-security/detect-prevent-and-mitigate-buffer-overflow-attacks/[41]',
            references:[{name:'CWE-170: Improper Null Termination', link:'https://cwe.mitre.org/data/definitions/170.html'}],
            examples:[
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following code reads from cfgfile and copies the input into inputbuf using strcpy(). The code mistakenly assumes that inputbuf will always contain a NULL terminator.',
                    postText: 'The code above will behave correctly if the data read from cfgfile is null terminated on disk as expected. But if an attacker is able to modify this input so that it does not contain the expected NULL character, the call to strcpy() will continue copying from memory until it encounters an arbitrary NULL character. This will likely overflow the destination buffer and, if the attacker can control the contents of memory immediately following inputbuf, can leave the application susceptible to a buffer overflow attack.',
                    code: '#define MAXLEN 1024\n' +
                        '...\n' +
                        'char *pathbuf[MAXLEN];\n' +
                        '...\n' +
                        'read(cfgfile,inputbuf,MAXLEN); //does not null terminate\n' +
                        'strcpy(pathbuf,inputbuf); //requires null terminated input\n' +
                        '...'
                },
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'In the following code, readlink() expands the name of a symbolic link stored in pathname and puts the absolute path into buf. The length of the resulting value is then calculated using strlen().',
                    postText: 'The code above will not always behave correctly as readlink() does not append a NULL byte to buf. Readlink() will stop copying characters once the maximum size of buf has been reached to avoid overflowing the buffer, this will leave the value buf not NULL terminated. In this situation, strlen() will continue traversing memory until it encounters an arbitrary NULL character further on down the stack, resulting in a length value that is much larger than the size of string. Readlink() does return the number of bytes copied, but when this return value is the same as stated buf size (in this case MAXPATH), it is impossible to know whether the pathname is precisely that many bytes long, or whether readlink() has truncated the name to avoid overrunning the buffer. In testing, vulnerabilities like this one might not be caught because the unused contents of buf and the memory immediately following it may be NULL, thereby causing strlen() to appear as if it is behaving correctly.',
                    code: 'char buf[MAXPATH];\n' +
                        '...\n' +
                        'readlink(pathname, buf, MAXPATH);\n' +
                        'int length = strlen(buf);\n' +
                        '...'
                },
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'While the following example is not exploitable, it provides a good example of how nulls can be omitted or misplaced, even when "safe" functions are used:',
                    postText: 'The above code gives the following output: "The last character in shortString is: n (6e)". So, the shortString array does not end in a NULL character, even though the "safe" string function strncpy() was used. The reason is that strncpy() does not impliciitly add a NULL character at the end of the string when the source is equal in length or longer than the provided size.',
                    code: '#include <stdio.h>\n' +
                        '#include <string.h>\n' +
                        '\n' +
                        'int main() {\n' +
                        '\n' +
                        'char longString[] = "String signifying nothing";\n' +
                        'char shortString[16];\n' +
                        '\n' +
                        'strncpy(shortString, longString, 16);\n' +
                        'printf("The last character in shortString is: %c (%1$x)\\n", shortString[15]);\n' +
                        'return (0);\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Unchecked Return Value',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type =="tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type =="tm.SmartWatch") || (el.element.attributes.type== "tm.Laptop") || (el.element.attributes.type =="tm.Tablet") || (el.element.attributes.type =="tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.9',
            title:'Unchecked Return Value',
            type:'Tampering',
            status:'Open',
            severity:'Low',
            description:'The software does not check the return value froma method or function, which can prevent it fromdetecting unexpected states and conditions. Twocommon programmer assumptions are \"thisfunction call can never fail\" and \"it doesn\'tmatter if this function call fails\". If an attacker canforce the function to fail or otherwise return a valuethat is not expected, then the subsequent programlogic could lead to a vulnerability, because thesoftware is not in a state that the programmerassumes. For example, if the program calls afunction to drop privileges but does not check thereturn code to ensure that privileges weresuccessfully dropped, then the program willcontinue to operate with the higher privileges. [40]',
            mitigation:'To mitigate this threat, three techniques must beapplied to all functions in the given program that isbeing evaluated:Ensure all of the functions that return a value,actually return a value and confirm that the value isexpected.Ensure within each function, that the possible ofreturn values are coveredWithin each function, ensure that there is acheck/default value when there is an error. [40]',
            references:[{name:'CWE-252: Unchecked Return Value', link:'https://cwe.mitre.org/data/definitions/252.html'}],
            examples:[
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'Consider the following code segment:',
                    postText: 'The programmer expects that when fgets() returns, buf will contain a null-terminated string of length 9 or less. But if an I/O error occurs, fgets() will not null-terminate buf. Furthermore, if the end of the file is reached before any characters are read, fgets() returns without writing anything to buf. In both of these situations, fgets() signals that something unusual has happened by returning NULL, but in this code, the warning will not be noticed. The lack of a null terminator in buf can result in a buffer overflow in the subsequent call to strcpy().',
                    code: 'char buf[10], cp_buf[10];\n' +
                        'fgets(buf, 10, stdin);\n' +
                        'strcpy(cp_buf, buf);'
                },
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following code does not check to see if memory allocation succeeded before attempting to use the pointer returned by malloc().',
                    postText: 'The traditional defense of this coding error is: "If my program runs out of memory, it will fail. It doesn\'t matter whether I handle the error or simply allow the program to die with a segmentation fault when it tries to dereference the null pointer." This argument ignores three important considerations:\n' +
                        '\n' +
                        'Depending upon the type and size of the application, it may be possible to free memory that is being used elsewhere so that execution can continue.\n' +
                        'It is impossible for the program to perform a graceful exit if required. If the program is performing an atomic operation, it can leave the system in an inconsistent state.\n' +
                        'The programmer has lost the opportunity to record diagnostic information. Did the call to malloc() fail because req_size was too large or because there were too many requests being handled at the same time? Or was it caused by a memory leak that has built up over time? Without handling the error, there is no way to know.',
                    code: 'buf = (char*) malloc(req_size);\n' +
                        'strncpy(buf, xfer, req_size);'
                }
            ]
        });});

    flow.rule('Unsafe JNI',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","java"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "java"))) || (el.element.attributes.type == "tm.SmartWatch"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "java"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","java"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "java"))) || (el.element.attributes.type ==  "tm.Electrocardiogram"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "java"))) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "java")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.10',
            title:'Unsafe JNI',
            type:'Denial of service',
            status:'Open',
            severity:'Low',
            description:'When a Java application uses the Java NativeInterface (JNI) to call code written in anotherprogramming language, it can expose theapplication to weaknesses in that code, even ifthose weaknesses cannot occur in Java. Manysafety features that programmers may take forgranted simply do not apply for native code, so youmust carefully review all such code for potentialproblems. The languages used to implement nativecode may be more susceptible to buffer overflowsand other attacks. Native code is unprotected bythe security features enforced by the runtimeenvironment, such as strong typing and arraybounds checking [42]',
            mitigation:'To mitigate this threat, three techniques must beapplied in the given program that is beingevaluated:Implement a form of error handling within each JNIcall.Avoid using any JNI calls if the native library isuntrusted.Seek an alternative to a JNI call such as using a JavaAPI.',
            references:[{name:'CWE-111: Direct Use of Unsafe JNI', link:'https://cwe.mitre.org/data/definitions/111.html'}],
            examples:[
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following code defines a class named Echo. The class declares one native method (defined below), which uses C to echo commands entered on the console back to the user. The following C code defines the native method implemented in the Echo class:',
                    code: '#include <jni.h>\n' +
                        '#include "Echo.h"//the java class above compiled with javah\n' +
                        '#include <stdio.h>\n' +
                        '\n' +
                        'JNIEXPORT void JNICALL\n' +
                        'Java_Echo_runEcho(JNIEnv *env, jobject obj)\n' +
                        '{\n' +
                        'char buf[64];\n' +
                        'gets(buf);\n' +
                        'printf(buf);\n' +
                        '}'
                },
            ]
        });});

    flow.rule('Unsafe use of reflection',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","c#, python, ruby, java, php"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "c#, python, ruby, java, php"))) || (el.element.attributes.type == "tm.SmartWatch"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "c#, python, ruby, java, php"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","c#, python, ruby, java, php"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "c#, python, ruby, java, php"))) || (el.element.attributes.type ==  "tm.Electrocardiogram"&& isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "c#, python, ruby, java, php"))) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "c#, python, ruby, java, php")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.11',
            title:'Unsafe use of reflection',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'This vulnerability is caused by unsafe use of thereflection mechanisms in programming languageslike Java, C#, or Ruby, etc. An attacker may be ableto create unexpected control flow paths throughthe application, potentially bypassing securitychecks. Exploitation of this weakness can result in alimited form of code injection. If an attacker cansupply values that the application then uses todetermine which class to instantiate or whichmethod to invoke, the potential exists for theattacker to create control flow paths through theapplication that were not intended by theapplication developers. This attack vector may allowthe attacker to bypass authentication or accesscontrol checks or otherwise cause the application tobehave in an unexpected manner. This situationbecomes a doomsday scenario if the attacker canupload files into a location that appears on theapplication\'s classpath or add new entries to theapplication\'s classpath. Under either of theseconditions, the attacker can use reflection tointroduce new, presumably malicious, behavior intothe application.[43]',
            mitigation:'Refactor your code to avoid using reflection.Do not use user-controlled inputs to select and loadclasses or code.Apply strict input validation by using whitelists orindirect selection to ensure that the user is onlyselecting allowable classes or code.[43]',
            references:[{name:'CWE-470: Use of Externally-Controlled Input to Select Classes or Code (\'Unsafe Reflection\')', link:'https://cwe.mitre.org/data/definitions/470.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'A common reason that programmers use the reflection API is to implement their own command dispatcher. The following example shows a command dispatcher that does not use reflection:',
                    code: 'String ctl = request.getParameter("ctl");\n' +
                        'Worker ao = null;\n' +
                        'if (ctl.equals("Add")) {\n' +
                        'ao = new AddCommand();\n' +
                        '}\n' +
                        'else if (ctl.equals("Modify")) {\n' +
                        'ao = new ModifyCommand();\n' +
                        '}\n' +
                        'else {\n' +
                        'throw new UnknownActionError();\n' +
                        '}\n' +
                        'ao.doAction(request);'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'A programmer might refactor this code to use reflection as follows:',
                    postText: 'The refactoring initially appears to offer a number of advantages. There are fewer lines of code, the if/else blocks have been entirely eliminated, and it is now possible to add new command types without modifying the command dispatcher. However, the refactoring allows an attacker to instantiate any object that implements the Worker interface. If the command dispatcher is still responsible for access control, then whenever programmers create a new class that implements the Worker interface, they must remember to modify the dispatcher\'s access control code. If they do not modify the access control code, then some Worker classes will not have any access control.',
                    code: 'String ctl = request.getParameter("ctl");\n' +
                        'Class cmdClass = Class.forName(ctl + "Command");\n' +
                        'Worker ao = (Worker) cmdClass.newInstance();\n' +
                        'ao.doAction(request);'
                },
                {
                    language: {name: 'Java', highlightAlias: 'bash'},
                    preText: 'One way to address this access control problem is to make the Worker object responsible for performing the access control check. An example of the re-refactored code follows:',
                    postText: 'Although this is an improvement, it encourages a decentralized approach to access control, which makes it easier for programmers to make access control mistakes. This code also highlights another security problem with using reflection to build a command dispatcher. An attacker can invoke the default constructor for any kind of object. In fact, the attacker is not even constrained to objects that implement the Worker interface; the default constructor for any object in the system can be invoked. If the object does not implement the Worker interface, a ClassCastException will be thrown before the assignment to ao, but if the constructor performs operations that work in the attacker\'s favor, the damage will already have been done. Although this scenario is relatively benign in simple applications, in larger applications where complexity grows exponentially it is not unreasonable that an attacker could find a constructor to leverage as part of an attack.',
                    code: 'String ctl = request.getParameter("ctl");\n' +
                        'Class cmdClass = Class.forName(ctl + "Command");\n' +
                        'Worker ao = (Worker) cmdClass.newInstance();\n' +
                        'ao.checkAccessControl(request);\n' +
                        'ao.doAction(request);'
                }
            ]
        });});

    flow.rule('Insecure Data Storage',[[Element, 'el','(el.element.attributes.type == "tm.Store" && isFalse(el.element.isEncryptedStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.1',
            title:'Insecure Data Storage',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'An adversary that has attained a lost/stolen mobiledevice; malware or another repackaged app actingon the adversary\'s behalf that executes on themobile device. If an adversary physically attains themobile device, the adversary hooks up the mobiledevice to a computer with freely available software.These tools allow the adversary to see all thirdparty application directories that often containstored personally identifiable information (PII), orpersonal health records (PHR). An adversary mayconstruct malware or modify a legitimate app tosteal such information assets.[46]',
            mitigation:'It is important to threat model your mobile app, OS,platforms and frameworks to understand theinformation assets the app processes and how theAPIs handle those assets. Determine how yourapplication or software handles the followinginformation:URL caching (both request and response);Keyboard press caching;Copy/Paste buffer caching;Application backgrounding;Intermediate dataLogging;HTML5 data storage;Browser cookie objects;Analytics data sent to 3rd parties.[46]',
            references:[{name:'Insecure Data Storage', link:'https://www.owasp.org/index.php/Mobile_Top_10_2016-M2-Insecure_Data_Storage'}]});});

    flow.rule('Improper Platform Usage',[[Element, 'el','(el.element.attributes.type == "tm.MobilePhone")|| (el.element.attributes.type == "tm.SmartWatch")|| (el.element.attributes.type == "tm.Tablet")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.2',
            title:'Improper Platform Usage',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'This category covers misuse of a platform feature orfailure to use platform security controls. It mightinclude Android intents, platform permissions,misuse of TouchID, the Keychain, or some othersecurity control that is part of the mobile operatingsystem. The defining characteristic of risks in thiscategory is that the platform (iOS, Android)provides a feature or a capability that isdocumented and well understood. The app fails touse that capability or uses it incorrectly. This differsfrom other mobile top ten risks because the designand implementation is not strictly the appdeveloper\'s issue.There are several ways that mobile apps canexperience this risk.Violation of published guidelines. All platforms havedevelopment guidelines for security (((Android)),((iOS))). If an app contradicts the best practicesrecommended by the manufacturer, it will beexposed to this risk. For example, there areguidelines on how to use the iOS Keychain or howto secure exported services on Android. Apps thatdo not follow these guidelines will experience thisrisk.Violation of convention or common practice: Not allbest practices are codified in manufacturerguidance. In some instances, there are de facto bestpractices that are common in mobile apps.Unintentional Misuse: Some apps intend to do theright thing but get some part of the implementationwrong. This could be a simple bug, like setting thewrong flag on an API call, or it could be amisunderstanding of how the protections work.[47]',
            mitigation:'To mitigate this threat, secure coding and properconfigurations must be used on the server side ofthe mobile application [47].',
            references:[{name:'Improper Platform Usage', link:'https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage'}]});});

    flow.rule('Insecure Communication',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow) && isFalse(el.element.isPublicNetwork)) ||(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow) && isFalse(el.element.wifiInterface)) ||(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow) && isFalse(el.element.bluetoothInterface)) ||(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow) && isFalse(el.element.cellularInterface))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.3',
            title:'Insecure Communication',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'When designing a mobile application, data iscommonly exchanged in a client-server fashion.When the solution transmits its data, it musttraverse the mobile device\'s carrier network andthe internet. Attackers may exploit thesevulnerabilities to intercept sensitive data such as:social security numbers, web surfing history, creditcard numbers, bank accounts, personal healthrecords such as medical conditions, insuranceinformation, prescription records, medical histories,test and laboratory result while travelling across thewire.[48]',
            mitigation:'Assume that the network layer is not secure and issusceptible to eavesdropping.Apply SSL/TLS to transport channels that the mobileapp will use to transmit sensitive information,session tokens, or other sensitive data to a backendAPI or web service.Account for outside entities like third-partyanalytics companies, social networks, etc. by usingtheir SSL versions when an application runs aroutine via the browser/webkit. Avoid mixed SSLsessions as they may expose the user\'s session ID.Use strong, industry standard cipher suites withappropriate key lengths.Use certificates signed by a trusted CA provider.Never allow self-signed certificates and considercertificate pinning for security consciousapplications.Always require SSL chain verification.Only establish a secure connection after verifyingthe identity of the endpoint server using trustedcertificates in the key chain.Alert users through the UI if the mobile app detectsan invalid certificate.Do not send sensitive data over alternate channels(e.g. SMS, MMS, or notifications).If possible, apply a separate layer of encryption toany sensitive data before it is given to the SSLchannel. If future vulnerabilities are discovered inthe SSL implementation, the encrypted data willprovide a secondary defense against confidentialityviolation.[48]',
            references:[{name:'Insecure Communication', link:'https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication'}]});});

    flow.rule('Insecure Authentication',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.providesAuthenticationMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.providesAuthenticationLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram))|| (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.4',
            title:'Insecure Authentication',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'Authentication vulnerabilities are exploited throughautomated attacks that use available or custom-built tools.Once the adversary understands how the authenticationscheme is vulnerable, they fake or bypass authentication bysubmitting service requests to the mobile app\'s backendserver and bypass any direct interaction with the mobile app.This submission process is typically done via mobile malwarewithin the device or botnets owned by the attacker.[49]',
            mitigation:'Avoid weak authentication patterns:If you are porting a web application to its mobile equivalent,authentication requirements of mobile applications shouldmatch that of the web application component. Therefore, itshould not be possible to authenticate with lessauthentication factors than the web browser.Authenticating a user locally can lead to client-side bypassvulnerabilities. If the application stores data locally, theauthentication routine can be bypassed on jailbroken devicesthrough run-time manipulation or modification of the binary.If there is a compelling business requirement for offlineauthentication, see M10 for additional guidance onpreventing binary attacks against the mobile app;Where possible, ensure that all authentication requests areperformed server-side. Upon successful authentication,application data will be loaded onto the mobile device. Thiswill ensure that application data will only be available aftersuccessful authentication;If client-side storage of data is required, the data will need tobe encrypted using an encryption key that is securely derivedfrom the user\'s login credentials. This will ensure that thestored application data will only be accessible uponsuccessfully entering the correct credentials. There areadditional risks that the data will be decrypted via binaryattacks. See M9 for additional guidance on preventing binaryattacks that lead to local data theft;Persistent authentication (Remember Me) functionalityimplemented within mobile applications should never store auser\'s password on the device;Ideally, mobile applications should utilize a device-specificauthentication token that can be revoked within the mobileapplication by the user. This will ensure that the app canmitigate unauthorized access from a stolen/lost device;Do not use any spoof-able values for authenticating a user.This includes device identifiers or geo-location;Persistent authentication within mobile applications shouldbe implemented as opt-in and not be enabled by default;If possible, do not allow users to provide 4-digit PIN numbersfor authentication passwords.Reinforce Authentication:Developers should assume all client-side authorization andauthentication controls can be bypassed by malicious users.Authorization and authentication controls must be re-enforced on the server-side whenever possible.Due to offline usage requirements, mobile apps may berequired to perform local authentication or authorizationchecks within the mobile app\'s code. If this is the case,developers should instrument local integrity checks withintheir code to detect any unauthorized code changes. See M9for more information about detecting and reacting to binaryattacks.[49]',
            references:[{name:'Insecure Authentication', link:'https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication [51] https://www.owasp.org/index.php/Mobile_Top_10_2014-M4'}]});});

    flow.rule('Insufficient Transport Layer Protection',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow) && isFalse(el.element.usesTLS))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.5',
            title:'Insufficient Transport Layer Protection',
            type:'Information disclosure',
            status:'Open',
            severity:'Medium',
            description:'When designing a mobile application, data iscommonly exchanged in a client-server fashion.When the solution transmits its data, it musttraverse the mobile device\'s carrier network andthe internet. Threat agents might exploitvulnerabilities to intercept sensitive data while it\'straveling across the wire. The following ways arepossible threat agents that exist:An adversary that shares your local network(compromised or monitored Wi-Fi);Carrier or network devices (routers, cell towers,proxy\'s, etc.); orMalware on your mobile device.[51]',
            mitigation:'General Best Practices:Assume that the network layer is not secure and issusceptible to eavesdropping.Apply SSL/TLS to transport channels that the mobileapp will use to transmit sensitive information,session tokens, or other sensitive data to a backendAPI or web service.Account for outside entities like third-partyanalytics companies, social networks, etc. by usingtheir SSL versions when an application runs aroutine via the browser\'s webkit. Avoid mixed SSLsessions as they may expose the user\'s session ID.Use strong, industry standard cipher suites withappropriate key lengths.Use certificates signed by a trusted CA provider.Never allow self-signed certificates and considercertificate pinning for security consciousapplications.Always require SSL chain verification.Only establish a secure connection after verifyingthe identity of the endpoint server using trustedcertificates in the key chain.Alert users through the UI if the mobile app detectsan invalid certificate.Do not send sensitive data over alternate channels(e.g, SMS, MMS, or notifications).If possible, apply a separate layer of encryption toany sensitive data before it is given to the SSLchannel. In the event that future vulnerabilities arediscovered in the SSL implementation, theencrypted data will provide a secondary defenseagainst confidentiality violation.iOS Specific Best Practices:Default classes in the latest version of iOS handleSSL cipher strength negotiation very well. Troublecomes when developers temporarily add code tobypass these defaults to accommodatedevelopment hurdles. In addition to the abovegeneral practices:Ensure that certificates are valid and fail closed.When using CFNetwork, consider using the SecureTransport API to designate trusted clientcertificates. In almost all situations,NSStreamSocketSecurityLevelTLSv1 should be usedfor higher standard cipher strength.After development, ensure all NSURL calls (orwrappers of NSURL) do not allow self-signed orinvalid certificates such as the NSURL class methodsetAllowsAnyHTTPSCertificate.Consider using certificate pinning by doing thefollowing: export your certificate, include it in yourapp bundle, and anchor it to your trust object.Using the NSURL methodconnection:willSendRequestForAuthenticationChallenge: will now accept your cert.Android Specific Best Practices:Remove all code after the development cycle thatmay allow the application to accept all certificatessuch asorg.apache.http.conn.ssl.AllowAllHostnameVerifierorSSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER. These are equivalent to trusting all certificates.If using a class which extends SSLSocketFactory,make sure checkServerTrusted method is properlyimplemented so that server certificate is correctlychecked.[51]',
            references:[]});});

    flow.rule('Unintended Data Leakage',[[Element, 'el','(el.element.attributes.type == "tm.Store")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.6',
            title:'Unintended Data Leakage',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Unintended data leakage occurs when a developerinadvertently places sensitive information or data ina location on the mobile device that is easilyaccessible by other apps on the device. Thisvulnerability is exploited by mobile malware,modified versions of legitimate apps, or anadversary that has physical access to the victim\'smobile device. In case the attacker has physicalaccess to the device, then the attacker can usefreely available forensic tools to conduct an attack.Another possible attack vector would be if anattacker has access to the device via malicious code,so they will use fully permissible and documentedAPI calls to conduct an attack. [51]',
            mitigation:'Threat model your OS, platforms, andframeworks to determine how they handle thefollowing features:URL Caching (Both request and response)Keyboard Press CachingCopy/Paste buffer CachingApplication backgroundingLoggingHTML5 data storageBrowser cookie objectsAnalytics data sent to 3rd partiesAlso identify what a given OS or framework doesby default, by doing this and applying mitigatingcontrols, unintended data leakage can beavoided. [51]',
            references:[]});});

    flow.rule('Broken/Insecure ',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.isEncryptedMobilePhone)&& isTrue(dropDownOptionsCheck("encryptionTypeForMobilePhone", "des, rsa, tripleDes,tripleDes3Key, rc2, rc4, 128rc4, desx")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.7',
            title:'Broken/Insecure ',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'This threat is cause when an adversary has physicalaccess to data that has been encrypted improperly,or mobile malware acting on an adversary\'s behalf.This can be done in several ways such as decryptionaccess to the device or network traffic capture, ormalicious apps on the device with access to theencrypted data Hello.',
            mitigation:'To mitigate this threat, avoid using algorithms orprotocols that are unsecure such as \'RC2\',\'MD4\', \'MD5\' and \'SHA1\'. A strongercryptographic algorithm that is widely known to besecure should be used. Currently, AES is one of themost secure encryption algorithms and isrecommended to be used.  [33] [34] [52]',
            references:[{name:'A Study of Encryption Algorithms (RSA', link:'DES'},{name:'Broken ', link:'https://www.owasp.org/index.php/Mobile_Top_10_2014-M6'},{name:'Using a broken or risky cryptographic algorithm', link:'https://www.owasp.org/index.php/Using_a_broken_or_risky_cryptographic_algorithm'}]});});

    flow.rule('Client-Side Injection',[[Element, 'el','(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.userInputMobilePhone) && isTrue(el.element.validatesInputMobilePhone))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.8',
            title:'Client-Side Injection',
            type:'Information disclosure',
            status:'Open',
            severity:'Medium',
            description:'Client-side injection results in the execution ofmalicious code on the mobile device via the mobileapp. Consider anyone who can send untrusted datato the mobile app, including external users, internalusers, the application itself or other malicious appson the mobile device. A possible attack vector couldbe an adversary loads simple text-based attacksthat exploit the syntax of the targeted interpreterwithin the mobile app. It is important to understandthat almost any source of data can be an injectionvector, including resource files or the applicationitself. [53]',
            mitigation:'IOS Specific Best Practices:SQLite Injection: When designing queries for SQLitebe sure that user supplied data is being passed to aparameterized query. This can be spotted bylooking for the format specifier used. In general,dangerous user supplied data will be inserted by a%@ instead of a proper parameterized queryspecifier.JavaScript Injection (XSS, etc): Ensure that allUIWebView calls do not execute without properinput validation. Apply filters for dangerousJavaScript characters if possible, using a whitelistover blacklist character policy before rendering. Ifpossible, call mobile Safari instead of rending insideof UIWebkit which has access to your application.Local File Inclusion: Use input validation forNSFileManager calls.XML Injection: use libXML2 over NSXMLParserFormat String Injection: Several Objective Cmethods are vulnerable to format string attacks:NSLog, [NSString stringWithFormat:], [NSStringinitWithFormat:], [NSMutableStringappendFormat:], [NSAlertinformativeTextWithFormat:], [NSPredicatepredicateWithFormat:], [NSException format:],NSRunAlertPanel.Do not let sources outside of your control, such asuser data and messages from other applications orweb services, control any part of your formatstrings.Classic C Attacks: Objective C is a superset of C,avoid using old C functions vulnerable to injectionsuch as: strcat, strcpy, strncat, strncpy, sprint,vsprintf, gets, etc.Android Specific Best Practices:SQL Injection: When dealing with dynamic queriesor Content-Providers ensure you are usingparameterized queries.JavaScript Injection (XSS): Verify that JavaScript andPlugin support is disabled for any WebViews(usually the default).Local File Inclusion: Verify that File System Access isdisabled for any WebViews(webview.getSettings().setAllowFileAccess(false);).Intent Injection\/Fuzzing: Verify actions and dataare validated via an Intent Filter for all Activities.Binary Injection\/Modification Prevention forAndroid and iOS:Follow security coding techniques for jailbreakdetection, checksum, certificate pinning, anddebugger detection controlsThe organization building the app must adequatelyprevent an adversary from analyzing and reverseengineering the app using static or dynamic analysistechniques.The mobile app must be able to detect at runtimethat code has been added or changed from whatit knows about its integrity at compile time. Theapp must be able to react appropriately atruntime to a code integrity violation.[53]',
            references:[{name:'Client Side Injection', link:'https://www.owasp.org/index.php/Mobile_Top_10_2014-M7'}]});});

    flow.rule('Poor Client ',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type =="tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type =="tm.SmartWatch") || (el.element.attributes.type== "tm.Laptop") || (el.element.attributes.type =="tm.Tablet") || (el.element.attributes.type =="tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.9',
            title:'Poor Client ',
            type:'Spoofing',
            status:'Open',
            severity:'Medium',
            description:'This threat involves entities that can pass untrustedinputs to method calls made within mobile code.These types of issues are not necessarily securityissues in and of themselves but lead to securityvulnerabilities. For example, buffer overflows withinolder versions of Safari (a poor code qualityvulnerability) led to high risk drive-by Jailbreakattacks. Poor code-quality issues are typicallyexploited via malware or phishing scams. Anattacker will typically exploit vulnerabilities in thiscategory by supplying carefully crafted inputs to thevictim. These inputs are passed onto code thatresides within the mobile device where exploitationtakes place. Typical types of attacks will exploitmemory leaks and buffer overflows.[54]',
            mitigation:'To mitigate this threat, the followingcountermeasures should be considered:Consistent coding patterns, standards in anorganizationWrite code that is legible and documentedAny code that requires a buffer, the length of theinput should be checked, and the length should berestricted.Use third party tools to find buffer overflows andmemory leaks.Prioritize to fix any buffer overflows and memoryleaks that are present in the code before moving onto other issues.',
            references:[{name:'Poor ', link:'https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality'}]});});

    flow.rule('Security Decisions Via Untrusted Inputs',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type =="tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type =="tm.SmartWatch") || (el.element.attributes.type== "tm.Laptop") || (el.element.attributes.type =="tm.Tablet") || (el.element.attributes.type =="tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.10',
            title:'Security Decisions Via Untrusted Inputs',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'This threat involves entities that can pass untrustedinputs to the sensitive method calls. Examples ofsuch entities include, but are not limited to, users,malware and vulnerable apps  An attacker withaccess to app can intercept intermediate calls andmanipulate results via parameter tampering. [58]',
            mitigation:'To mitigate this threat, avoid usingdepreciated/unsupported methods for eachplatform that the application is being used. As anexample, for iOS, avoid using the handleOpenURLmethod to process URL scheme calls. Find analternative method that is supported by theplatform [58].',
            references:[{name:'Security Decisions via Untrusted Inputs', link:'https://www.owasp.org/index.php/Mobile_Top_10_2014-M8'}]});});

    flow.rule('Improper Session Handling',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.isAWebApplication))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.11',
            title:'Improper Session Handling',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'Anyone or any mobile app with access to HTTP/Straffic, cookie data, etc.  Possible attack vectorsinclude physical access to the device, and networktraffic capture, or malware on the mobile device.Essentially an adversary that has access to thesession tokens can impersonate the user bysubmitting the token to the backend server for anysensitive transactions such as credit card paymentsor health information like EKG results sent to adoctor. [59]',
            mitigation:'Validate sessions on the backend by ensuring allsession invalidation events are executed on theserver side and not just on the mobile app.Add adequate timeout protection to prevent themalicious potential for an unauthorized user togain access to an existing session and assume therole of that user. Timeout periods varyaccordingly based on the application, but somegood guidelines are: 15 minutes for high securityapps, 30 minutes for medium security apps, and 1hour for low security apps.Properly reset cookies during authenticationstate changes, by destroying sessions on theserver side and making sure that the cookiespresented as a part of the previous sessions areno longer acceptedIn addition to properly invalidating tokens on theserver side during key application events, makesure tokens are generated properly by using well-established and industry standard methods ofcreating tokens. Visit the following websites formore details:https://www.pcisecuritystandards.org/documents/Tokenization_Product_Security_Guidelines.pdfand https:/ools.ietf.org/html/rfc7519 for JSONWeb Token (JWT) andhttps://www.ietf.org/rfc/rfc6750.txt for BearerToken Usage[59]',
            references:[{name:'Improper Session Handling', link:'https://www.owasp.org/index.php/Mobile_Top_10_2014-M9'}]});});

    flow.rule('Lack of Binary Protections',[[Element, 'el','(el.element.attributes.type == "tm.MobilePhone")|| (el.element.attributes.type == "tm.Tablet") ||(el.element.attributes.type == "tm.SmartWatch")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.12',
            title:'Lack of Binary Protections',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'This threat involves an adversary who will analyzeand reverse engineer a mobile app\'s code, thenmodify it to perform some hidden functionality. Themajority of mobile apps do not prevent anadversary from successfully analyzing, reverseengineering or modifying the app\'s binary code.[60]',
            mitigation:'To mitigate this threat from an adversary fromanalysis and reversing engineering the code, orunauthorized code modification, an applicationmust follow very secure guidelines to activate thefollowing mechanisms in a platform:Jailbreak Detection Controls;Checksum Controls;Certificate Pinning Controls;Debugger Detection ControlsThese controls also require that the applicationhave two more additional requirements. Firstly, theorganization that is making the app must attempt todeny the adversary to analyze and reverse engineerthe app using analysis techniques that can be staticor dynamic. Lastly, the app must be able todetermine at runtime if it\'s application code hasbeen modified or added and react accordingly. [60]',
            references:[{name:'Lack of Binary Protections', link:'https://www.owasp.org/index.php/Mobile_Top_10_2014-M10'}]});});

    flow.rule('Improper Output Neutralization for Logs',[[Element, 'el','(el.element.attributes.type == "tm.Store" && isTrue(el.element.isALogStore))  ||(el.element.attributes.type == "tm.Process"  && isTrue(el.element.isALog)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.isALogMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch"&& isTrue(el.element.isALogSmartPhone)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.isALogLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.isALogTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.isALogElectrocardiogram)) ||(el.element.attributes.type == "tm.Pacemaker"&& isTrue(el.element.isALogPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '8.1',
            title:'Improper Output Neutralization for Logs',
            type:'Repudiation',
            status:'Open',
            severity:'Medium',
            description:'The software does not neutralize or incorrectlyneutralizes output that is written to logs. [61]',
            mitigation:'To mitigate this threat, there are 2countermeasures that can be implemented. Firstly,any input should be assumed to be malicious. Allinput should be validated, where a whitelist shouldbe used to accept input based on specificrequirements. Properties that should be consideredinclude length, type, full range of accepted values,missing or extra input, syntax, consistency andconforming to business logic. Anothercountermeasure is to have the output encoded in aparticular format that a downstream consumer can',
            references:[{name:'CWE-117: Improper Output Neutralization for Logs', link:'https://cwe.mitre.org/data/definitions/117.html'}]});});

    flow.rule('Insufficient Logging ',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type =="tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type =="tm.SmartWatch") || (el.element.attributes.type== "tm.Laptop") || (el.element.attributes.type =="tm.Tablet") || (el.element.attributes.type =="tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '8.2',
            title:'Insufficient Logging ',
            type:'Repudiation',
            status:'Open',
            severity:'Medium',
            description:'When a security-critical event occurs, the softwareeither does not record the event or omits importantdetails about the event when logging it. [62]',
            mitigation:'To mitigate this threat, there are 2countermeasures that can be implemented. Firstly,logging should be centralized with different levels ofdetails. However, in a production environmentthere should be sufficient logging to allow systemadministrators to see attacks, diagnose and recoverfrom errors. [62]',
            references:[{name:'CWE-778: Insufficient Logging', link:'https://cwe.mitre.org/data/definitions/778.html'}]});});

    flow.rule('Information Exposure Through Log Files',[[Element, 'el','(el.element.attributes.type == "tm.Store" && isTrue(el.element.isALogStore))  ||(el.element.attributes.type == "tm.Process"  && isTrue(el.element.isALog)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.isALogMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch"&& isTrue(el.element.isALogSmartPhone)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.isALogLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.isALogTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.isALogElectrocardiogram)) ||(el.element.attributes.type == "tm.Pacemaker"&& isTrue(el.element.isALogPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '8.3',
            title:'Information Exposure Through Log Files',
            type:'Information disclosure',
            status:'Open',
            severity:'Medium',
            description:'Information written to log files can be of a sensitivenature and give valuable guidance to an attacker orexpose sensitive user information. [64]',
            mitigation:'To mitigate this threat, there are a few mitigationsthat can be implemented. Firstly, anysensitive/secret information should not be writteninto any log files. Any debug log files should beremoved prior to code being deployed in aproduction environment. Log files should beprotected from unauthorized read/write access.Configurations should be changed when anapplication is transitioning to a productionenvironment. [63]',
            references:[{name:'CWE-532: Information Exposure Through Log Files', link:'https://cwe.mitre.org/data/definitions/532.html'},{name:'CWE-779: Logging of Excessive Data', link:'https://cwe.mitre.org/data/definitions/779.html'}]});});

    flow.rule('Logging of Excessive Data',[[Element, 'el','(el.element.attributes.type == "tm.Store" && isTrue(el.element.isALogStore))  ||(el.element.attributes.type == "tm.Process"  && isTrue(el.element.isALog)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.isALogMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch"&& isTrue(el.element.isALogSmartPhone)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.isALogLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.isALogTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.isALogElectrocardiogram)) ||(el.element.attributes.type == "tm.Pacemaker"&& isTrue(el.element.isALogPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '8.4',
            title:'Logging of Excessive Data',
            type:'Repudiation',
            status:'Open',
            severity:'Low',
            description:'The software logs too much information, making logfiles hard to process and possibly hinderingrecovery efforts or forensic analysis after an attack.[64]',
            mitigation:'To mitigate this threat, there are a few mitigationsthat can be implemented. Firstly, large log filesshould be replaced with regularly commissionedsummaries. Lastly, The log file\’s size should berestricted and controlled by a system administrator.[64]',
            references:[{name:'CWE-779: Logging of Excessive Data', link:'https://cwe.mitre.org/data/definitions/779.html'}]});});

    flow.rule('Not using password aging',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.1',
            title:'Not using password aging',
            type:'Spoofing',
            status:'Open',
            severity:'Low',
            description:'If no mechanism is in place for managing passwordaging, users will have no incentive to updatepasswords in a timely manner [65]',
            mitigation:'To mitigate this threat, an algorithm that wouldcheck how old a particular password is, should beimplemented and used regularly. This algorithmmust notify the user when their password is old andto change the password while not allowing the userto reuse old passwords as their new password [65].',
            references:[{name:'CWE-262: Not Using Password Aging', link:'https://cwe.mitre.org/data/definitions/262.html'}]});});

    flow.rule('Password Aging with Long Expiration',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.2',
            title:'Password Aging with Long Expiration',
            type:'Spoofing',
            status:'Open',
            severity:'Low',
            description:'Allowing password aging to occur unchecked canresult in the possibility of diminished passwordintegrity [66].',
            mitigation:'To mitigate this threat, there should be a maximumage that a password can be valid for (ex: 4 months)before the user has to change it. An algorithmshould be implemented to check the password\’sage and notify users prior to expiration of thatpassword [66].',
            references:[{name:'CWE-263: Password Aging with Long Expiration', link:'https://cwe.mitre.org/data/definitions/263.html'}]});});

    flow.rule('Authentication Bypass Using an Alternate Path orChannel',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop"&& isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.3',
            title:'Authentication Bypass Using an Alternate Path orChannel',
            type:'Spoofing',
            status:'Open',
            severity:'Medium',
            description:'A product requires authentication, but the producthas an alternate path or channel that does notrequire authentication [68].',
            mitigation:'To mitigate this threat, all access is suggested to gothrough a centralized point of access, where eachaccess of a resource requires a check to see if theuser has permission to access that resource [68].',
            references:[{name:'CWE-288: Authentication Bypass Using an Alternate Path or Channel', link:'https://cwe.mitre.org/data/definitions/288.html'}]});});

    flow.rule('Authentication Bypass by Alternate Name',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop"&& isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.4',
            title:'Authentication Bypass by Alternate Name',
            type:'Spoofing',
            status:'Open',
            severity:'Medium',
            description:'The software performs authentication based on thename of a resource being accessed, or the name ofthe actor performing the access, but it does notproperly check all possible names for that resourceor actor [69].',
            mitigation:'To mitigate this threat, avoid hardcoding names ofresources that are being accessed, if they can havealternate names [69].',
            references:[{name:'CWE-289: Authentication Bypass by Alternate Name', link:'https://cwe.mitre.org/data/definitions/289.html'}]});});

    flow.rule('Authentication Bypass by Capture-Replay',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop"&& isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.5',
            title:'Authentication Bypass by Capture-Replay',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'A capture-replay flaw exists when the design of thesoftware makes it possible for a malicious user tosniff network traffic and bypass authentication byreplaying it to the server in question to the sameeffect as the original message (or with minorchanges). [71]',
            mitigation:'To mitigate this threat, a timestamp and orchecksum with each response and check to see ifit\’s an old request to stop a replay of the sameauthentication process [71].',
            references:[{name:'CWE-294: Authentication Bypass by Capture-replay', link:'https://cwe.mitre.org/data/definitions/294.html'}]});});

    flow.rule('Reflection Attack in an Authentication Protocol',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop"&& isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.6',
            title:'Reflection Attack in an Authentication Protocol',
            type:'Spoofing',
            status:'Open',
            severity:'Medium',
            description:'Simple authentication protocols are subject toreflection attacks if a malicious user can use thetarget machine to impersonate a trusted user [72].',
            mitigation:'To mitigate this threat, there a few mitigations thatcan be used. Firstly, it is recommended to havedifferent keys for the requestor and responder of achallenge. Another suggestion is to providedifferent challenges for the requestor andresponder. Prior to the challenge, it isrecommended to have the requestor prove it\’sidentity. [72]',
            references:[{name:'CWE-301: Reflection Attack in an Authentication Protocol', link:'https://cwe.mitre.org/data/definitions/301.html'}]});});


    flow.rule('Authentication Bypass by Assumed-ImmutableData',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop"&& isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.7',
            title:'Authentication Bypass by Assumed-ImmutableData',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'The authentication scheme or implementation useskey data elements that are assumed to beimmutable, but can be controlled or modified bythe attacker [73].',
            mitigation:'To mitigate this threat, any immutable data fieldsshould be properly protected such as environmentvariables, and form fields to ensure that those fieldsare not tempered with [73].',
            references:[{name:'CWE-302: Authentication Bypass by Assumed-Immutable Data', link:'https://cwe.mitre.org/data/definitions/302.html'}]});});

    flow.rule('Incorrect Implementation of AuthenticationAlgorithm',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop"&& isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.8',
            title:'Incorrect Implementation of AuthenticationAlgorithm',
            type:'Spoofing',
            status:'Open',
            severity:'Low',
            description:'The requirements for the software dictate the useof an established authentication algorithm, but theimplementation of the algorithm is incorrect. [74]',
            mitigation:'To mitigate this threat, the algorithm should be fullytested, from endpoint to endpoint in a pre-production environment prior to being deployed ina production environment.',
            references:[{name:'CWE-303: Incorrect Implementation of Authentication Algorithm', link:'https://cwe.mitre.org/data/definitions/303.html'}]});});

    flow.rule('Missing Authentication for Critical Function',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Store" && isFalse(el.element.providesAuthenticationStore))|| (el.element.attributes.type == "tm.MobilePhone" && isFalse(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type =="tm.SmartWatch" && isFalse(el.element.providesAuthenticationSmartWatch))  || (el.element.attributes.type == "tm.Laptop"&& isFalse(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isFalse(el.element.providesAuthenticationTablet))|| (el.element.attributes.type =="tm.Electrocardiogram" && isFalse(el.element.providesAuthenticationElectrocardiogram))  || (el.element.attributes.type =="tm.Pacemaker" && isFalse(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.9',
            title:'Missing Authentication for Critical Function',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'The software does not perform any authenticationfor functionality that requires a provable useridentity or consumes a significant amount ofresources [75].',
            mitigation:'To mitigate this threat there are several countermeasures that can be implemented. Firstly, theapplication should be split up based on privilegelevels where it\’s maintained by a centralizedauthentication mechanism. Secondly, any securitycheck that was implemented on the client side of anapplication should also be on the server side.Another migration technique is to avoid designingand implementing authentication function that arecustom-tailed to the application. Lastly, any libraryor framework which is known to have countermeasures that will have the authentication function[75].',
            references:[{name:'CWE-306: Missing Authentication for Critical Function', link:'https://cwe.mitre.org/data/definitions/306.html'}]});});

    flow.rule('Improper Restriction of Excessive AuthenticationAttempts',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop"&& isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.10',
            title:'Improper Restriction of Excessive AuthenticationAttempts',
            type:'Spoofing',
            status:'Open',
            severity:'Medium',
            description:'The software does not implement sufficientmeasures to prevent multiple failed authenticationattempts within in a short time frame, making itmore susceptible to brute force attacks [76].',
            mitigation:'To mitigate this threat, there are multipletechniques can be used such as disconnecting theuser after a certain number of failed attempts,having a timeout after a certain number of attemptsor locking out a targeted account [76].',
            references:[{name:'CWE-307: Improper Restriction of Excessive Authentication Attempts', link:'https://cwe.mitre.org/data/definitions/307.html'}]});});

    flow.rule('Use of Single-Factor Authentication',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop"&& isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.11',
            title:'Use of Single-Factor Authentication',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'The use of single-factor authentication can lead tounnecessary risk of compromise when comparedwith the benefits of a dual-factor authenticationscheme [77].',
            mitigation:'To mitigate this threat, the system or applicationshould use an extra method of authentication(multi-factor authentication). This ensures if onemethod is compromised, the system or applicationis still safe [77].',
            references:[{name:'CWE-308: Use of Single-factor Authentication', link:'https://cwe.mitre.org/data/definitions/308.html'}]});});

    flow.rule('Key Exchange with Entity Authentication',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop"&& isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.12',
            title:'Key Exchange with Entity Authentication',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'The software performs a key exchange with anactor without verifying the identity of that actor[78].',
            mitigation:'There are two ways to mitigate this threat. Firstly,ensure when designing the system there isauthentication involved. Lastly, validate that thechecks that are actually verifying the identify of theuser when communicating between identities [78].',
            references:[{name:'CWE-322: Key Exchange without Entity Authentication', link:'https://cwe.mitre.org/data/definitions/322.html'}]});});

    flow.rule('Weak Password Requirements',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop"&& isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.13',
            title:'Weak Password Requirements',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'The product does not require that users shouldhave strong passwords, which makes it easier forattackers to compromise user accounts [80].',
            mitigation:'To mitigate this threat, a password policy must bein place to have strong passwords. [80].A password policy (rules to make strongpasswords) should in place to make a passwordmuch harder to guess for an attacker.Such an example of a password policy is asfollows:All passwords should be reasonably complexand difficult for unauthorized people toguess. Employees and pupils should choosepasswords that are at least eight characterslong and contain a combination of upper-and lower-case letters, numbers, andpunctuation marks and other specialcharacters. These requirements will beenforced with software when possible. [1]',
            references:[{name:'Password Policy', link:'https://www.gloucestershire.gov.uk/media/8868/password_policy-67251.docx'},{name:'CWE-521: Weak Password Requirements', link:'https://cwe.mitre.org/data/definitions/521.html'}]});});

    flow.rule('Use of Client-Side Authentication',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.14',
            title:'Use of Client-Side Authentication',
            type:'Spoofing',
            status:'Open',
            severity:'Medium',
            description:'A client/server product performs authenticationwithin client code but not in server code, allowingserver-side authentication to be bypassed via amodified client that omits the authentication check[81].',
            mitigation:'To mitigate this threat, authentication must also beperformed on the server side of the application orsystem. [81]',
            references:[{name:'CWE-521: Weak Password Requirements', link:'https://cwe.mitre.org/data/definitions/603.html'}]});});

    flow.rule('Unverified Password Change',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.15',
            title:'Unverified Password Change',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'When setting a new password for a user, theproduct does not require knowledge of the originalpassword, or using another form of authentication.[82]',
            mitigation:'To mitigate this threat, two techniques can beimplemented. Firstly, when there is a passwordchange, the user must provide the originalpassword. Lastly, a “Forget Password” option canbe used, but ensure that the user is requesting achange through a challenge (ex: enter email toreceive an email which contains a link to changetheir password) and not actually changing theuser\’s properties until they\’ve clicked that link[82].',
            references:[{name:'CWE-620: Unverified Password Change', link:'https://cwe.mitre.org/data/definitions/620.html'}]});});

    flow.rule('Weak Password Recovery Mechanism forForgetten Password',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.16',
            title:'Weak Password Recovery Mechanism forForgetten Password',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'The software contains a mechanism for users torecover or change their passwords without knowingthe original password, but the mechanism is weak[83].',
            mitigation:'To mitigate this threat, there are several countermeasures that can be implemented. Ensure that allthe input that goes through the mechanism isvalidated. If security questions are used, ensurethat the questions are not simple and there aremultiple questions. There should be a limit as tohow many attempts one has to answer a question.The user must also answer the question before thepassword is reset. Do not allow the user to choosewhich email the password is sent to. As well, theoriginal password should not be given, instead anew temporary password should be provided [83].',
            references:[{name:'CWE-640: Weak Password Recovery Mechanism for Forgotten Password', link:'https://cwe.mitre.org/data/definitions/640.html'}]});});

    flow.rule('External Control of System or ConfigurationSetting',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isFalse(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isFalse(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone"&& isFalse(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type =="tm.Pacemaker" && isFalse(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type =="tm.SmartWatch" && isFalse(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isFalse(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isFalse(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isFalse(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.1',
            title:'External Control of System or ConfigurationSetting',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'One or more system settings or configurationelements can be externally controlled by a user[84].',
            mitigation:'To mitigate this threat, the system can be split upby privilege level, so the settings/control are onlychanged by authorized users. [84]',
            references:[{name:'CWE-15: External Control of System or Configuration Setting', link:'https://cwe.mitre.org/data/definitions/15.html'}]});});

    flow.rule('Process Control',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type =="tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type =="tm.SmartWatch") || (el.element.attributes.type== "tm.Laptop") || (el.element.attributes.type =="tm.Tablet") || (el.element.attributes.type =="tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.2',
            title:'Process Control',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'Executing commands or loading libraries from anuntrusted source or in an untrusted environmentcan cause an application to execute maliciouscommands (and payloads) on behalf of an attacker[85].',
            mitigation:'To mitigate this threat, libraries and frameworksthat are used must be from a trusted source, wherethese libraries can be relied upon and not bemaliciously used by an adversary. [85]',
            references:[{name:'CWE-114: Process Control', link:'https://cwe.mitre.org/data/definitions/114.html'}]});});

    flow.rule('Sensitive Data Under Web Root',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.isAWebApplication))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.3',
            title:'Sensitive Data Under Web Root',
            type:'Information disclosure',
            status:'Open',
            severity:'Medium',
            description:'The application stores sensitive data under the webdocument root with insufficient access control,which might make it accessible to untrusted parties.[86]',
            mitigation:'To mitigate this threat, avoid storing informationunder the web root directory, and access controlsshould be implemented to not allow these files tobe read or written to [86]',
            references:[{name:'CWE-219: Sensitive Data Under Web Root', link:'https://cwe.mitre.org/data/definitions/219.html'}]});});

    flow.rule('Incorrect Privilege Assignment',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.4',
            title:'Incorrect Privilege Assignment',
            type:'Elevation of privilege',
            status:'Open',
            severity:'High',
            description:'A product incorrectly assigns a privilege to aparticular actor, creating an unintended sphere ofcontrol for that actor [87].',
            mitigation:'To mitigate this threat, the settings, managementsand handling of privileges must be managedcarefully. There should be accounts with limitedprivileges if there is a task that needs to be done,with very specific privilege levels. [87]',
            references:[{name:'CWE-266: Incorrect Privilege Assignment', link:'https://cwe.mitre.org/data/definitions/266.html'}]});});

    flow.rule('Privilege Defined With Unsafe Actions',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type =="tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type =="tm.SmartWatch") || (el.element.attributes.type== "tm.Laptop") || (el.element.attributes.type =="tm.Tablet") || (el.element.attributes.type =="tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.5',
            title:'Privilege Defined With Unsafe Actions',
            type:'Elevation of privilege',
            status:'Open',
            severity:'High',
            description:'A particular privilege, role, capability, or right canbe used to perform unsafe actions that were notintended, even when it is assigned to the correctentity [88].',
            mitigation:'To mitigate this threat, the settings, managementsand handling of privileges must be managedcarefully. There should be accounts with limitedprivileges if there is a task that needs to be done,with very specific privilege levels [88].',
            references:[{name:'CWE-267: Privilege Defined With Unsafe Actions', link:'https://cwe.mitre.org/data/definitions/267.html'}]});});

    flow.rule('Privilege Chaining',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type =="tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type =="tm.SmartWatch") || (el.element.attributes.type== "tm.Laptop") || (el.element.attributes.type =="tm.Tablet") || (el.element.attributes.type =="tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.6',
            title:'Privilege Chaining',
            type:'Elevation of privilege',
            status:'Open',
            severity:'High',
            description:'Two distinct privileges, roles, capabilities, or rightscan be combined in a way that allows an entity toperform unsafe actions that would not be allowedwithout that combination [89].',
            mitigation:'To mitigate this threat, the settings, managementsand handling of privileges must be managedcarefully. There should be accounts with limitedprivileges if there is a task that needs to be done,with very specific privilege levels. In addition tothose techniques, privileges should be separatedwhere multiple conditions need to be met to access[89].',
            references:[{name:'CWE-268: Privilege Chaining', link:'https://cwe.mitre.org/data/definitions/268.html'}]});});

    flow.rule('Improper Privilege Management',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isFalse(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isFalse(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone"&& isFalse(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type =="tm.Pacemaker" && isFalse(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type =="tm.SmartWatch" && isFalse(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isFalse(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isFalse(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isFalse(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.7',
            title:'Improper Privilege Management',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The software does not properly assign, modify,track, or check privileges for an actor, creating anunintended sphere of control for that actor [90].',
            mitigation:'To mitigate this threat three techniques arepossible counter measures to properly manageprivileges. There should be specific trust zones inthe system, the least privilege principle should be ineffect where the access rights of each user aregiven the minimum privilege level to do their task aswell, privileges should be separated where multipleconditions need to be met to access [90].',
            references:[{name:'CWE-269: Improper Privilege Management', link:'https://cwe.mitre.org/data/definitions/269.html'}]});});

    flow.rule('Privilege Context Switching Error',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.8',
            title:'Privilege Context Switching Error',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The software does not properly manage privilegeswhile it is switching between different contexts thathave different privileges or spheres of control [91].',
            mitigation:'To mitigate this threat, three techniques arepossible counter measures to properly manageprivileges in different contexts. There should bespecific trust zones in the system, the least privilegeprinciple should be in effect where the access rightsof each user are given the minimum privilege levelto do their task as well, privileges should beseparated where multiple conditions need to bemet to access [91].',
            references:[{name:'CWE-270: Privilege Context Switching Error', link:'https://cwe.mitre.org/data/definitions/270.html'}]});});

    flow.rule('Privilege Dropping or Lowering Errors',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.9',
            title:'Privilege Dropping or Lowering Errors',
            type:'Elevation of privilege',
            status:'Open',
            severity:'High',
            description:'The software does not drop privileges beforepassing control of a resource to an actor that doesnot have those privileges [92].',
            mitigation:'To mitigate this threat, three techniques arepossible counter measures to properly manageprivileges in different contexts. There should bespecific trust zones in the system, the least privilegeprinciple should be in effect where the access rightsof each user are given the minimum privilege levelto do their task as well, privileges should beseparated where multiple conditions need to bemet to access [92].',
            references:[{name:'CWE-271: Privilege Dropping / Lowering Errors', link:'https://cwe.mitre.org/data/definitions/271.html'}]});});

    flow.rule('Improper Check for Dropped Privileges',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.10',
            title:'Improper Check for Dropped Privileges',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The software attempts to drop privileges but doesnot check or incorrectly checks to see if the dropsucceeded [93].',
            mitigation:'To mitigate this threat, there are two techniquesthat can counter against an improper check fordropped privileges. Firstly, the system should bedesigned from the point of view of privilege level,where there are entry points and trust boundariesto interface components of different privilegelevels. Ensure that all functions return a value, andverify that the result is expected [93].',
            references:[{name:'CWE-273: Improper Check for Dropped Privileges', link:'https://cwe.mitre.org/data/definitions/273.html'}]});});

    flow.rule('Incorrect Default Permissions',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.11',
            title:'Incorrect Default Permissions',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The software, upon installation, sets incorrectpermissions for an object that exposes it to anunintended actor [94].',
            mitigation:'To mitigate the threat of default permissions thesettings, management and handling of privilegesshould be carefully managed [94].',
            references:[{name:'CWE-276: Incorrect Default Permissions', link:'https://cwe.mitre.org/data/definitions/276.html'}]});});

    flow.rule('Insecure Inherited Permissions',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.12',
            title:'Insecure Inherited Permissions',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Low',
            description:'A product defines a set of insecure permissions thatare inherited by objects that are created by theprogram [95].',
            mitigation:'To mitigate this threat, the settings, managementand handling of privileges need to be managedproperly [95].',
            references:[{name:'CWE-277: Insecure Inherited Permissions', link:'https://cwe.mitre.org/data/definitions/277.html'}]});});

    flow.rule('Incorrect Execution-Assigned Permissions',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.13',
            title:'Incorrect Execution-Assigned Permissions',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'While it is executing, the software sets thepermissions of an object in a way that violates theintended permissions that have been specified bythe user [96].',
            mitigation:'To mitigate this threat, the settings, managementand handling of privileges need to be managedproperly [96].',
            references:[{name:'CWE-279: Incorrect Execution-Assigned Permissions', link:'https://cwe.mitre.org/data/definitions/279.html'}]});});

    flow.rule('Improper Handling of Insufficient Permissions orPrivileges',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.14',
            title:'Improper Handling of Insufficient Permissions orPrivileges',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The application does not handle or incorrectlyhandles when it has insufficient privileges to accessresources or functionality as specified by theirpermissions. This may cause it to follow unexpectedcode paths that may leave the application in aninvalid state [97].',
            mitigation:'To mitigate this threat, there should be areas wherethere are specific permission levels. In addition,verify that if an access to a resource or systemfunctionality is successful or not in all privilegelevels. [97]',
            references:[{name:'CWE-280: Improper Handling of Insufficient Permissions or Privileges', link:'https://cwe.mitre.org/data/definitions/280.html'}]});});

    flow.rule('Improper Ownership Management',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone"&& isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type =="tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type =="tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.15',
            title:'Improper Ownership Management',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The software assigns the wrong ownership, or doesnot properly verify the ownership, of an object orresource [98].',
            mitigation:'To mitigate this threat, the settings, managementand handling of privilege needs to managedcarefully [98].',
            references:[{name:'CWE-282: Improper Ownership Management ', link:'https://cwe.mitre.org/data/definitions/282.html'}]});});

    flow.rule('Unverified Ownership',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isFalse(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isFalse(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone"&& isFalse(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type =="tm.Pacemaker" && isFalse(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type =="tm.SmartWatch" && isFalse(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isFalse(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isFalse(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type =="tm.Electrocardiogram" && isFalse(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.16',
            title:'Unverified Ownership',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Low',
            description:'The software does not properly verify that a criticalresource is owned by the proper entity [99].',
            mitigation:'To mitigate the threat of unverified ownership, thesettings, management and handling of privilegeneeds to be managed carefully and the applicationneeds to be designed from a separation of privilegepoint of view, which will require multiple conditionsto access a resource. [99]',
            references:[{name:'CWE-283: Unverified Ownership', link:'https://cwe.mitre.org/data/definitions/283.html'}]});});





});

}
}

module.exports = threatengine;
