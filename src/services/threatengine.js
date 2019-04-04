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

    flow.rule('Proper Classification of Medical Device ',[[Element, 'el','el.element.attributes.type == "tm.SmartWatch" || el.element.attributes.type== "tm.Pacemaker" || el.element.attributes.type == "tm.Electrocardiogram"|| el.element.attributes.type == "tm.MobilePhone" ||el.element.attributes.type == "tm.Laptop" || el.element.attributes.type == "tm.Tablet"'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '0.1',
            title:'Proper Classification of Medical Device ',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Federal governments provide different classifications and requirements for medical devices. When building a medical device, it is important to classify the device you are building to ensure the system meets standards defined by the main regulatory body in your operating regions. The threat Your system or device will fail certification.',
            mitigation:'Classify your eHealth device before development. Consult the most recent guidance documents provided by the Government of Canada to aid in classifying your device and understanding the system requirements.',
            references:[]});});

    flow.rule('Compliance in the Collection and Storage of Electronic Health Records',[[Element, 'el','el.element.attributes.type == "tm.SmartWatch" ||el.element.attributes.type == "tm.Pacemaker" || el.element.attributes.type == "tm.Electrocardiogram" || el.element.attributes.type == "tm.MobilePhone" || el.element.attributes.type == "tm.Laptop" ||el.element.attributes.type == "tm.Tablet"'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '0.2',
            title:'Compliance in the Collection and Storage of Electronic Health Records',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Depending on the nation and region of subject data collection and storage (local or remote), specific operating rules may apply. For example: In the storage of electronic health records in Canada, specific rules and legislation are put into place varying by province or territory and continuously change over time. The legislation is written through discussion of principles of consent to collection, limited use, security safeguards, and patient participation.',
            mitigation:'Legal council is required when defining User Agreements and when engineering specific rules of collection or storage to ensure all defined standards and criterion are met for the region(s) of operation.',
            references:[]});});

    flow.rule('CDP Manipulation',[[Element, 'el','el.element.attributes.type == "tm.Process" && isTrue(el.element.isANetworkSwitch)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '0.3',
            title:'CDP Manipulation',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'CDP Manipulation: CDP packets are enabled on all interfaces by default on Cisco switches and they are transmitted in clear text which allows an attacker to analyze the packets and gain a wealth of information about the network device then the attacker can use this information to execute a known vulnerability against the device platform.',
            mitigation:'Solution is to disable CDP on non-management interfaces.',
            references:[]});});

    flow.rule('MAC Flooding',[[Element, 'el','el.element.attributes.type == "tm.Process" && isTrue(el.element.isANetworkSwitch)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '0.4',
            title:'MAC Flooding',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'MAC Flooding: Here the attacker floods the CAM table with MAC addresses more than the switch can store which leads to the switch operating as hub giving the attacker the opportunity to sniff all traffic on the segment.',
            mitigation:'Configuring Port Security: It involves limiting the NO. of MACs allowed through a port and can also specify what is the MAC/MACs are. The switch port have to be in access mode, when a violation occurs one of 3 actions is taken based on your configuration (shutdown, protect or restrict). The default action is to shut down the port and a log message will appear, protect means ignore the violated MAC but there is no way to tell us that a violation had occurred, restrict is the same as protect but it adds a counter to the violation counter and a log message will appear also. If a port is shut down due to violation it has to be manually re opened using the shutdown and no shutdown commands in the same sequence or using the (config) #errdisablerecovery cause security-violation then to set the recover interval (config )#errdisablerecovery interval {time in sec} and to verify the error disable recovery state #sh errdisablerecovery.ii- Port Base Authentication or 80',
            references:[]});});

    flow.rule('VLAN Based Attacks',[[Element, 'el','el.element.attributes.type == "tm.Process" && isTrue(el.element.isANetworkSwitch)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '0.5',
            title:'VLAN Based Attacks',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'VLAN hopping: Is when a station is able to access VLAN other than its own. This can be done through one of the following: A- Switch spoofing:A PC will claim to establish a trunk link between itself and the switch and gain all the VLAN informations trying to get benefit of the switch default interfaces state (dynamic auto/desirable).802.11 Double tagging: Here the attacker/computer double tags the frame with the native VLAN on its trunk link and the second tag is for the destined victim VLAN, when the frame reaches the first switch it\'s rips off the first tag and forward it to all the trunk links configured for the native VLAN and when it reaches the second switch it will see the second tag and forward the fame to the victim VLAN.',
            mitigation:'VLAN Hopping:  Is to Disable the DTP messages on trunk ports (using no negotiate),and avoid the switch defaults (dynamic auto/desirable) regarding trunk links as possible, a better approach is to hardcode the ports. ii-Configure all the ports that should connect to end stations as access, assign them to an unused VLAN and shut them down. Double Tagging:I- The same steps as the switch spoofing. ii-Configuring VACL (VLAN Access ControlList). iii- Private VLAN, PVLANs allows you to divide a VLAN into secondary VLANs,letting you isolate a set of ports from other ports within the same VLAN, we create a primary VLAN and a secondary VLANs as desired, we can have one isolated per primary but we can have as many ports in the isolated as desired, private VLAN can only be configured on switches in transparent VTP mode, ports within private VLAN can be one of three: - Community: communicates with other community ports and promiscuous ports. - Isolated: communicates with promiscuous only.- Promiscuous: communicates with all ports.',
            references:[]});});

    flow.rule('Empty String Password',[[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials) && isTrue(el.element.remoteMedicalRecordStorage)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '1.1',
            title:'Empty String Password',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Using an empty string as a password is insecure.It is never appropriate to use an empty string as a password. It is too easy to guess. An empty string password makes the authentication as weak with the user names which are normally public or guessable. This makes a brute-force attack against the login interface much easier.',
            mitigation:'To counter this threat, a password that is not an empty string should be used. Users are suggested to have passwords with at least eight characters long. It is not appropriate to have an empty string as a password [79].',
            references:[{name:'CWE-258: Empty Password in Configuration File', link:'https://cwe.mitre.org/data/definitions/258.html'}]});});

    flow.rule('Password in Configuration File',[[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials) && isTrue(el.element.checkboxRemoteMedicalRecordStorage)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '1.2',
            title:'Password in Configuration File',
            type:'Information disclosure',
            status:'Open',
            severity:'Medium',
            description:'Storing a password in a configuration file allows anyone who can read the file access to the password-protected resource. Developers sometimes believe that they cannot defend the application from someone who has access to the configuration, but this attitude makes an attacker\'s job easier.',
            mitigation:'To mitigate this threat, 2 mitigations are required.The configuration file needs to employ a form of access control to ensure only those who have the privilege to access that file, are the only ones allowed to access that. To control the information contained in the configuration file, the passwords should be stored in encrypted text which will combine the use of hash functions and the use of salts to take any password of any size and produce a unique hash value of the password and combine it with the original password, that way the password cannot be determined from the file.',
            references:[{name:'Advances of Password Cracking and Countermeasures in Computer Security', link:'https://arxiv.org/pdf/1411.7803.pdf'}]});});

    flow.rule('Hardcoded Password',[[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials) && isTrue(el.element.checkboxRemoteMedicalRecordStorage)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '1.3',
            title:'Hardcoded Password',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Hardcoded passwords may compromise system security in a way that cannot be easily remedied.It is never a good idea to hard code a password. Not only does hardcoding a password allow all the project\'s developers to view the password, it also makes fixing the problem extremely difficult. Once the code is in production,the password cannot be changed without patching the software. If the account protected by the password is compromised, the owners of the system will be forced to choose between security and availability.',
            mitigation:'To counter this threat of hardcoding passwords, there are several mitigations/countermeasures that can be implemented:Ask user for the password. The program should not know the password of a user. The user should be presented with a challenge to enter their password for the program to not be compromised easily [5].If an existing password is stored on an Authentication distributed server such as an AFS (Andrew Filesystem [6]) or Kerberos, obtain the passwords from the server. Have the password stored in a separate configuration file, where that file is strictly read access only and has a level of access control that only certain individuals and processes who have the right privilege can read the file [5].',
            references:[{name:'Alternatives to Hardcoding Passwords', link:'https://security.web.cern.ch/security/recommendations/en/password_alternatives.shtml'},{name:'AFS: The Andrew Filesystem', link:'https://stuff.mit.edu/afs/sipb/project/doc/guide/guide/node12.html'}]});});

    flow.rule('Password Plaintext Storage',[[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentialsStore)'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '1.4',
            title:'Password Plaintext Storage',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Storing a password in plaintext may result in a system compromise.Password management issues occur when a password is stored in plaintext in an application\'s properties or configuration file. A programmer can attempt to remedy the password management problem by obscuring thepassword with an encoding function, such as base 64 encoding, but this effort does not adequately protect the password.',
            mitigation:'Passwords should never be stored in plain text.Rather these passwords should be stored in encrypted text which will combine the use of hash functions and the use of salts to take any password of any size and produce a unique hash value of the password and combine it with the original password, that way the password cannot be determined from the file. [2]',
            references:[{name:'Advances of Password Cracking and Countermeasures in Computer Security', link:'https://arxiv.org/pdf/1411.7803.pdf'}]});});

    flow.rule('Least Privilege Violation',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) || (el.element.attributes.type==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.privilegeLevelForMobilePhone)) ||(el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) || (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '1.5',
            title:'Least Privilege Violation',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The elevated privilege level required to perform operations such as chroot()should be dropped immediately after the operation is performed.When a program calls a privileged function, such as chroot(), it must first acquire root privilege. As soon as the privileged operation has completed,the program should drop root privilege and return to the privilege level of the invoking user.',
            mitigation:'There are several ways to mitigate the least privilege violation:Split an individual components into several components, and assign lower privilege levels to those components [8].Identify areas in the system which have that elevated privilege and use those  components instead to accomplish the task [8].Create a separate environment within the system/program where only within that area or environment has an elevated privilege [8].',
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

    flow.rule('Code Permission',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.privilegeLevelForProcess)) || (el.element.attributes.type ==  "tm.Actor" && isFalse(el.element.privilegeLevelForActor)) || (el.element.attributes.type == "tm.Store" && isFalse(el.element.privilegeLevelForStore)) || (el.element.attributes.type == "tm.MobilePhone" && isFalse(el.element.privilegeLevelForMobilePhone)) ||(el.element.attributes.type == "tm.Pacemaker" && isFalse(el.element.privilegeLevelForPacemaker)) || (el.element.attributes.type == "tm.SmartWatch" && isFalse(el.element.privilegeLevelForSmartWatch)) ||(el.element.attributes.type == "tm.Laptop" && isFalse(el.element.privilegeLevelForLaptop)) || (el.element.attributes.type == "tm.Tablet" && isFalse(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isFalse(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '1.6',
            title:'Code Permission',
            type:'Elevation of privilege, Information Disclosure',
            status:'Open',
            severity:'High',
            description:'An active developer with access to unrelated module code may tamper or disclose sensitive project information (Interproject Code Access).',
            mitigation:'Throughout the development lifecycle, there are several mitigations that can be used:Within the Implementation phase, if a critical resource is being used, there should be a check to see if a resource has permissions/behavior which are not secure (such as a regular user being able to modify that resource). If there are such behaviors or permissions that exist, the program should create an error or exit the program [10].Within the Architecture and Design phase, one should split up the software components based on privilege level and if possible, control what data,functions and resources each component uses based the privilege level [10].Another option in this phase is to create a separate environment within the system/program where only within that area or environment has an elevated privilege [8].In the installation phase, default or most restrictive permissions should be set to avoid any code which doesn\'t have the permissions to be run. Also, the assumption that a system administrator will change the settings based on a manual is incorrect [10].In the System Configuration phase, The configurable, executable files and libraries should be only have read and write access by the system administrator. In the Documentation phase, within any documentation, any configurations that are suggested must be secure, and do not affect the operation of the computer or program [10].',
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

    flow.rule('Double Free Error',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","c, c++, assembly"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "c, c++, assembly"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "c, c++, assembly"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","c, c++, assembly"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "c,c++, assembly"))) || (el.element.attributes.type ==  "tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "c, c++, assembly"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "c, c++, assembly")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.1',
            title:'Double Free Error',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'Double free errors occur when free() is called more than once with the same memory address as an argument. Calling free() twice on the same value can lead to memory leak. When a program calls free() twice with the same argument, the program\'s memory management data structures become corrupted and could allow a malicious user to write values in arbitrary memory spaces. This corruption can cause the program to crash or, in some circumstances, alter the execution flow. By overwriting registers or memory spaces, an attacker can trick the program into executing code of his/her own choosing, often resulting in an interactive shell with elevated permissions.When a buffer is free(), a linked list of free buffers is read to rearrange and combine the chunks of free memory (to be able to allocate larger buffers in the future). These chunks are laid out in a double linked list which points to previous and next chunks. Unlinking an unused buffer (which is what happens when free() is called) could allow an attacker to write arbitrary values in memory; essentially overwriting valuable registers, calling shellcode from its own buffer.',
            mitigation:'To mitigate this threat, each allocation should only be freed once. Once the memory has been allocated, the pointer should be set to NULL to ensure the pointer cannot be freed again. In complicated error conditions, ensure that clean-up routines represent the state of allocation. If the language is object oriented, that object destructors delete each allocation of memory one time only.',
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

    flow.rule('Leftover Debug Code',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.SmartWatch")|| (el.element.attributes.type == "tm.Pacemaker") || (el.element.attributes.type == "tm.Electrocardiogram") ||(el.element.attributes.type == "tm.MobilePhone") ||(el.element.attributes.type == "tm.Laptop") ||(el.element.attributes.type == "tm.Tablet")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.2',
            title:'Leftover Debug Code',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'Debug code can create unintended entry points in a deployed web application.A common development practice is to add \"backdoor\" code specifically designed for debugging or testing purposes that is not intended to be shipped or deployed with the application. When this sort of debug code is accidentally left in the application, the application is open to unintended modes of interaction. These back-door entry points create security risks because they are not considered during design or testing and fall outside of the expected operating conditions of the application.',
            mitigation:'To mitigate this threat, all debug code should be removed prior to delivery of code.',
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

    flow.rule('Memory Leak',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess", "c, c++"))) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "c, c++"))) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforSmartWatch", "c, c++"))) ||(el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforLaptop", "c, c++"))) ||(el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforTablet", "c, c++"))) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforElectrocardiogram", "c, c++")))|| (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforPacemaker", "c, c++")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.3',
            title:'Memory Leak',
            type:'Denial of service',
            status:'Open',
            severity:'High',
            description:'A memory leak is an unintentional form of memory consumption whereby the developer fails to free an allocated block of memory when no longer needed. The consequences of such an issue depend on the application itself. Consider the following general three cases:Short Lived User-land Application: Little if any noticeable effect. Modern operating system recollects lost memory after program termination. Long Lived User-land Application: Potentially dangerous; These applications continue to waste memory over time, eventually consuming all RAM resources. Leads to abnormal system behavior.Kernel-land Process: Memory leaks in the kernel level lead to serious system stability issues. Kernel memory is very limited compared to user land memory and should be handled cautiously.Memory is allocated but never freed. Memory leaks have two common and sometimes overlapping causes: Error conditions and other exceptional circumstances. Confusion over which part of the program is responsible for freeing the memory. Most memory leaks result in general software reliability problems, but if an attacker can intentionally trigger a memory leak, the attacker might be able to launch a denial of service attack (by crashing the program) or take advantage of other unexpected program behavior resulting from a low memory condition.',
            mitigation:'To mitigate that threat, 3rd party tools/software are required to see if this vulnerability exists in the code. One such tool that can be used in aUnix/Linux environment is a program calledValgrind. This program will run the desired software program to be checked to check all memory allocation and de-allocation methods are working as intended.',
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

    flow.rule('Null Dereference',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.SmartWatch")|| (el.element.attributes.type == "tm.PaceMaker") || (el.element.attributes.type == "tm.Electrocardiogram") ||(el.element.attributes.type == "tm.MobilePhone") ||(el.element.attributes.type == "tm.Laptop") ||(el.element.attributes.type == "tm.Tablet")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.4',
            title:'Null Dereference',
            type:'Denial of service',
            status:'Open',
            severity:'Medium',
            description:'The program can potentially dereference a null pointer, thereby raising a NullPointerException.Null pointer errors are usually the result of one or more programmer assumptions being violated. Most null pointer issues result in general software reliability problems, but if an attacker can intentionally trigger a null pointer dereference, the attacker might be able to use the resulting exception to bypass security logic or to cause the application to reveal debugging information that will be valuable in planning subsequent attacks.A null-pointer dereference takes place when a pointer with a value of NULL is used as though it pointed to a valid memory area.Null-pointer dereferences, while common, can generally be found and corrected in a simple way. They will always result in the crash of the process, unless exception handling (on some platforms) is invoked, and even then, little can be done to salvage the process.',
            mitigation:'To mitigate this threat, if possible, this vulnerability would be prevented, if the programming language that was used to program the software did not use pointers. Another mitigation suggestion is to check to see if the pointers are referenced correctly prior to their use [14].',
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

    flow.rule('Logging Practices',[[Element, 'el','(el.element.attributes.type == "tm.Store" && isTrue(el.element.isALogStore))  ||(el.element.attributes.type == "tm.Process"  && isTrue(el.element.isALog)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.isALogMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.isALogSmartPhone)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.isALogLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.isALogTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.isALogElectrocardiogram)) ||(el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.isALogPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.5',
            title:'Logging Practices',
            type:'Repudiation',
            status:'Open',
            severity:'Low',
            description:'Declare Logger Object as Static and Final:It is good programming practice to share a single logger object between all of the instances of a particular class and to use the same logger for the duration of the program. Don\'t Use Multiple Loggers: It is a poor logging practice to use multiple loggers rather than logging levels in a single class.Good logging practice dictates the use of a singlelogger that supports different logging levels foreach class.Don\'t Use System Output Stream:Using System.out or System.err rather than a dedicated logging facility makes it difficult to monitor the behavior of the program. It can also cause log messages accidentally returned to the end users, revealing internal information to attackers. While most programmers go on to learn many nuances and subtleties about Java, a surprising number hang on to this first lesson and never give up on writing messages to standard output using System.out.println(). The problem is that writing directly to standard output or standard error is often used as an unstructured form of logging. Structured logging facilities provide features like logging levels,uniform formatting, a logger identifier,timestamps, and, perhaps most critically, the ability to direct the log messages to the right place. When the use of system output streams is jumbled together with the code that uses loggers properly, the result is often a well-kept log that is missing critical information. In addition, using system output streams can also cause log messages accidentally returned to end users,revealing application internal information to attackers. Developers widely accept the need for structured logging, but many continue to use system output streams in their \"pre-production\" development. If the code you are reviewing is past the initial phases of development, use of System.out or System.err may indicate an oversight in the moveto a structured logging system.',
            mitigation:'To mitigate this threat the logging system should be centralized to the program and give different levels of detail, and log/display all security successes or failures.',
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

    flow.rule('Unreleased Resource',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.usesExternalResourcesProcess)&& isTrue(el.element.usesResourcesDirectlyProcess))|| (el.element.attributes.type == "tm.Store"  && isTrue(el.element.usesExternalResourcesStore)&& isTrue(el.element.usesResourcesDirectlyStore))|| (el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.usesExternalResourcesMobilePhone) && isTrue(el.element.usesResourcesDirectlyMobilePhone)) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.usesExternalResourcesSmartWatch) && isTrue(el.element.usesResourcesDirectlySmartWatch)) || (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.usesExternalResourcesLaptop)&& isTrue(el.element.usesResourcesDirectlyLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.usesExternalResourcesTablet)&& isTrue(el.element.usesResourcesDirectlyTablet))|| (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.usesExternalResourcesElectrocardiogram) && isTrue(el.element.usesResourcesDirectlyElectrocardiogram)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.usesExternalResourcesPacemaker) && isTrue(el.element.usesResourcesDirectlyPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.6',
            title:'Unreleased Resource',
            type:'Denial of service',
            status:'Open',
            severity:'Medium',
            description:'Most unreleased resource issues result in general software reliability problems, but if an attacker can intentionally trigger a resource leak, the attacker might be able to launch a denial of service attack by depleting the resource pool. Resource leaks have at least two common causes: Error conditions and other exceptional circumstances.Confusion over which part of the program is responsible for releasing the resource.',
            mitigation:'To mitigate this threat, the programming language used to program the desired program, should not allow this threat to occur. Another suggestion is to free all resources that have been allocated and be consistent in terms of how memory is allocated and de-allocated. To furthermore mitigate this threat, a suggestion is to release all the member components of a given object.',
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

    flow.rule('Use of Obsolete Methods',[[Element, 'el','el.element.attributes.type == "tm.Store"  || el.element.attributes.type == "tm.Process" || (el.element.attributes.type == "tm.SmartWatch")|| (el.element.attributes.type == "tm.PaceMaker") || (el.element.attributes.type == "tm.Electrocardiogram") ||(el.element.attributes.type == "tm.MobilePhone") ||(el.element.attributes.type == "tm.Laptop") ||(el.element.attributes.type == "tm.Tablet")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '2.7',
            title:'Use of Obsolete Methods',
            type:'Denial of service',
            status:'Open',
            severity:'Medium',
            description:'The use of deprecated or obsolete functions may indicate neglected code.As programming languages evolve, functions occasionally become obsolete due to: Advances in the languageImproved understanding of how operations should be performed effectively and securelyChanges in the conventions that govern certain operations, Functions that are removed are usually replaced by newer counterparts that perform the same task in some different and hopefully improved way.Refer to the documentation for this function in order to determine why it is deprecated or obsolete and to learn about alternative ways to achieve the same functionality. The remainder of this text discusses general problems that stem from the use of deprecated or obsolete functions.',
            mitigation:'To mitigate this threat, the documentation for the program should be referred to, to determine the reason it is deprecated and to determine alternatives to using those methods, which may pose not only a function concern, but also a security concern.',
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
            description:'Information exposure through query strings in URLis when sensitive data is passed to parameters in the URL. This allows attackers to obtain sensitive data such as usernames, passwords, tokens (authX),database details, and any other potentially sensitive data. Simply using HTTPS does not resolve this vulnerability. A very common example is in GET requests.',
            mitigation:'To mitigate this threat, it is recommended to use aPOST method, as those parameters that are passed in through the URL are not saved, and therefore cannot be exposed.',
            references:[{name:'CWE-598: Information Exposure Through Query Strings in GET Request', link:'https://cwe.mitre.org/data/definitions/598.html'}]});});

    flow.rule('Improper Certificate Validation',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.validatesCertProcess)) ||(el.element.attributes.type == "tm.Store" && isFalse(el.element.validatesCertStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '3.2',
            title:'Improper Certificate Validation',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'The software does not validate, or incorrectly validates, a certificate.',
            mitigation:'Certificates should be carefully managed and check to assure that data a re-encrypted with the intended owner\'spublic key. If certificate pinning is being used, ensure that all relevant properties of the certificate are fully validated before the certificate is pinned, including the hostname.',
            references:[{name:'CWE-295: Improper Certificate Validation', link:'https://cwe.mitre.org/data/definitions/295.html'}]});});

    flow.rule('Insufficient TLS Protection',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Flow" && isFalse(el.element.usesTLS))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '3.3',
            title:'Insufficient TLS Protection',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Sensitive data must be protected when it is transmitted through the network. Such data can include user credentials and credit cards. As a rule of thumb, if data must be protected when it is stored, it must be protected also during transmission. HTTP is a clear-text protocol and it is normally secured via an SSL/TLS tunnel, resulting in HTTPS traffic. The use of this protocol ensures not only confidentiality, but also authentication. Servers are authenticated using digital certificates and it is also possible to use client certificate for mutual authentication. Even if high grade ciphers are today supported and normally used, some misconfiguration in the server can be used to force the use of a weak cipher - or at worst no encryption - permitting to an attacker to gain access to the supposed secure communication channel. Other misconfiguration can be used for a Denial of Service attack. See: https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001) for more information',
            mitigation:'To mitigate this threat, web servers that provide https services should have their configuration checked. As well, the validity of an SSL certificate should be checked from a client and server point of view. These would be checked using a variety of tools which are found on the following website :https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)  [31]',
            references:[{name:'Testing for Weak SSL/TLS Ciphers Insufficient Transport Layer Protection (OTG-CRYPST-001)', link:'https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)'}]});});

    flow.rule('Hard-coded Cryptographic Key',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.isEncryptedMobilePhone))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.isEncryptedActor)) ||(el.element.attributes.type == "tm.Flow"  && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm. SmartWatch" && isTrue(el.element.isEncryptedSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.isEncryptedLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.isEncryptedTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.isEncryptedElectrocardiogram))||(el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.isEncryptedPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '3.4',
            title:'Hard-coded Cryptographic Key',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'The use of a hard-coded cryptographic key tremendously increases the possibility that encrypted data may be recovered.If hard-coded cryptographic keys are used, it is almost certain that malicious users will gain access through the account in question.',
            mitigation:'To mitigate against this threat, this practice of hardcoding the cryptographic key should be avoided to avoid exposing the cryptographic key to a potential adversary for exploitation.',
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

    flow.rule('Faulty Cryptographic Algorithm',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.isEncryptedMobilePhone)&& isTrue(dropDownOptionsCheck("encryptionTypeForMobilePhone", "des, rsa, tripleDes,tripleDes3Key, rc2, rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Process" && isTrue(el.element.isEncryptedProcess) && isTrue(dropDownOptionsCheck("encryptionTypeForProcess", "des, rsa, tripleDes, tripleDes3Key,rc2, rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Actor" && isTrue(el.element.isEncryptedActor) && isTrue(dropDownOptionsCheck("encryptionTypeForActor", "des, rsa, tripleDes, tripleDes3Key, rc2,rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Store" && isTrue(el.element.isEncryptedStore) && isTrue(dropDownOptionsCheck("encryptionTypeForStore", "des, rsa, tripleDes, tripleDes3Key, rc2,rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Flow" && isTrue(el.element.isEncryptedFlow) && isTrue(dropDownOptionsCheck("encryptionTypeForFlow", "des, rsa, tripleDes, tripleDes3Key, rc2,rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.SmartWatch" && isTrue(el.element.isEncryptedSmartWatch)&& isTrue(dropDownOptionsCheck("encryptionTypeForSmartWatch", "des, rsa, tripleDes,tripleDes3Key, rc2, rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Laptop" && isTrue(el.element.isEncryptedLaptop) && isTrue(dropDownOptionsCheck("encryptionTypeForLaptop", "des, rsa, tripleDes, tripleDes3Key,rc2, rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Tablet" && isTrue(el.element.isEncryptedTablet) && isTrue(dropDownOptionsCheck("encryptionTypeForTablet", "des, rsa, tripleDes, tripleDes3Key, rc2,rc4, 128rc4, desx"))) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.isEncryptedElectrocardiogram)&& isTrue(dropDownOptionsCheck("encryptionTypeForElectrocardiogram", "des, rsa, tripleDes,tripleDes3Key, rc2, rc4, 128rc4, desx"))) ||(el.element.attributes.type == " tm.Pacemaker" && isTrue(el.element.isEncryptedPacemaker) && isTrue(dropDownOptionsCheck("encryptionTypeForStore", "des, rsa, tripleDes, tripleDes3Key, rc2,rc4, 128rc4, desx")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '3.5',
            title:'Faulty Cryptographic Algorithm',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Attempting to create non-standard and non-tested algorithms, using weak algorithms, or applying algorithms incorrectly will pose a high weakness to data that is meant to be secure.',
            mitigation:'To mitigate this threat, a stronger cryptographic algorithm that is widely known to be secure should be used. Currently, AES is one of the most secure encryption algorithms and is recommended to be used.',
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
            description:'The application configuration should ensure thatSSL is used for all access-controlled pages.If an application uses SSL to guarantee confidential communication with client browsers, the application configuration should make it impossible to view any access-controlled page without SSL.However, it is not an uncommon problem that the configuration of the application fails to enforce the use of SSL on pages that contain sensitive data.There are three common ways for SSL to be bypassed: A user manually enters the URL and types \"HTTP\"rather than \"HTTPS\".Attackers intentionally send a user to an insecureURL.A programmer erroneously creates a relative link toa page in the application, failing to switch fromHTTP to HTTPS. (This is particularly easy to do when the link moves between public and secured a reason a web site.)',
            mitigation:'The first and foremost control that needs to be applied is to check for a lack of transport encryption. This can be done by: Reviewing network traffic of the device, its mobile application and any cloud connections to determine if any information is passed in cleartextReviewing the use of SSL or TLS to ensure it is up to date and properly implementedReviewing the use of any encryption protocols to ensure they are recommended and acceptedIn order to ensure enough transport encryption:Ensuring data is encrypted using protocols such asSSL and TLS while transiting networks.Ensuring other industry standard encryption techniques are utilized to protect data during transport if SSL or TLS are not available.Ensuring only accepted encryption standards are used and avoid using proprietary encryption protocols.Ensuring the message payload encryptionEnsuring the secure encryption key handshaking.Ensuring received data integrity verification.',
            references:[{name:'Insecure Transport', link:'https://vulncat.fortify.com/en/detail?id=desc.controlflow.cpp.insecure_transport_weak_ssl_protocol#Swift'}]});});

    flow.rule('Path Traversal',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.localAccessProcess) && isFalse(el.element.validatesInputProcess)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.localAccessStore) && isFalse(el.element.validatesInputStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.localAccessMobilePhone) && isFalse(el.element.validatesInputMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.localAccessSmartWatch) && isFalse(el.element.validatesInputSmartWatch)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.localAccessLaptop) && isFalse(el.element.validatesInputLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.localAccessTablet) && isFalse(el.element.validatesInputTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.localAccessElectrocardiogram) && isFalse(el.element.validatesInputElectrocardiogram))|| (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.localAccessPacemaker) && isFalse(el.element.validatesInputPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '4.2',
            title:'Path Traversal',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'Allows attackers to access files that are not intended tobe accessed. The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory. By using special elements such as \"..\" and \"/\" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. One of the most common special elements is the\"../\" sequence, which in most modern operating systems is interpreted as the parent directory of the current location. This is referred to as relative path traversal. Path traversal also covers the use of absolute pathnames such as \"/usr/local/bin\", which may also be useful in accessing unexpected files. This is referred to as absolute path traversal.',
            mitigation:': Assume all input is malicious. Use an\"accept known good\" input validation strategy, i.e.,use a whitelist of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications or transform it into something that does. When performing input validation, consider all potentially relevant properties,including length, type of input, the full range of acceptable values, missing or extra inputs, syntax,consistency across related fields, and conformance to business rules. As an example of business rule logic,\"boat\" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as\"red\" or \"blue.\" Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a blacklist). A blacklist is likely to miss at least one undesirable input, especially if the code\'senvironment changes. This can give attackers enough room to bypass the intended validation. However,blacklists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid.Use an application firewall that can detect attacks against this weakness. It can be beneficial in cases in which the code cannot be fixed (because it is controlled by a third party), as an emergency prevention measure while more comprehensive software assurance measures are applied, or to provide defense in depth.Run your code using the lowest privileges that are required to accomplish the necessary tasks. If possible,create isolated accounts with limited privileges that are only used for a single task. That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment. For example, database applications rarely need to run as the database administrator, especially in day-to-day operations. Run the code in a \"jail\" or similar sandbox environment that enforces strict boundaries between the process and the operating system. This may effectively restrict which files can be accessed in a directory or which command can be executed by the software. OS-level examples include the Unix chrootjail, AppArmor, and SELinux. In general, managed code may provide some protection. For example,java.io.FilePermission in the Java SecurityManager allows the software to specify restrictions on fileoperations.Attack Surface Reduction: Store library, include, and utility files outside of the web document root, if possible. Otherwise, store them in a separate directory and use the web server\'s access control capabilities to prevent attackers from directly requesting them. One common practice is to define a fixed constant in each calling program, then check for the existence of the constant in the library/include file; if the constant does not exist, then the file was directly requested, and it can exit immediately. This significantly reduces the chance of an attacker being able to bypass any protection mechanisms that are in the base program but not in the include files. It will also reduce the attack surface. Ensure that error messages only contain minimal details that are useful to the intended audience, and nobody else. The messages need to strike the balance between being too cryptic and not being cryptic enough. They should not necessarily reveal the methods that were used to determine the error. Such detailed information can be used to refine the original attack to increase the chances of success. In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the filesystem hierarchy.',
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

    flow.rule('Exposure of Private Information (Privacy Violation)',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isFalse(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isFalse(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isFalse(el.element.privilegeLevelForMobilePhone)) ||(el.element.attributes.type == "tm.Pacemaker" && isFalse(el.element.privilegeLevelForPacemaker)) ||(el.element.attributes.type == "tm.SmartWatch" && isFalse(el.element.privilegeLevelForSmartWatch)) ||(el.element.attributes.type == "tm.Laptop" && isFalse(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isFalse(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isFalse(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '4.3',
            title:'Exposure of Private Information (Privacy Violation)',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'The software does not properly prevent private data(such as credit card numbers) from being accessed by actors who either (1) are not explicitly authorized to access the data or (2) do not have the implicit consent of the people to which the data is related. Mishandling private information, such as customer passwords or SocialSecurity numbers, can compromise user privacy and is often illegal. An exposure of private information does not necessarily prevent the software from working properly,and in fact it might be intended by the developer, but it can still be undesirable (or explicitly prohibited by law) for the people who are associated with this private information. Some examples of private information include: social security numbers, web surfing history,credit card numbers, bank accounts, personal health records such as medical conditions, insurance information, prescription records, medical histories, test and laboratory results.',
            mitigation:'Separation of Privilege by compartmentalizing the system to have \"safe\" areas where trust boundaries can be unambiguously drawn. Do not allow sensitive data to go outside of the trust boundary and always be careful when interfacing with a compartment outside of the safe area.Ensure that appropriate compartmentalization is built into the system design and that the compartmentalization serves to allow for and further reinforce privilege separation functionality. Architects and designers should rely on the principle of least privilege to decide when it is appropriate to use and to drop system privileges.',
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

    flow.rule('Catch NullPointerException',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess", "objectivec,c#, java, python"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforSmartWatch","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforLaptop","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforTablet","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforElectrocardiogram","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforPacemaker","objectivec, c#, java, python")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '5.1',
            title:'Catch NullPointerException',
            type:'Denial of service',
            status:'Open',
            severity:'Medium',
            description:'It is generally a bad practice to catch NullPointerException. Programmers typically catchNullPointerException under three circumstances:The program contains a null pointer dereference. Catching the resulting exception was easier than fixing the underlying problem.The program explicitly throws a NullPointerException to signal an error condition.The code is part of a test harness that supplies unexpected input to the classes under test.This is the only acceptable scenario.[15]',
            mitigation:'Do not extensively rely on catching exceptions (especially for validating user input) to handle errors. Handling exceptions can decrease the performance of an application.[15]',
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

    flow.rule('Empty Catch Block',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess", "objectivec,c#, java, python"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforSmartWatch","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforLaptop","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforTablet","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforElectrocardiogram","objectivec, c#, java, python"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageforPacemaker","objectivec, c#, java, python")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '5.2',
            title:'Empty Catch Block',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'The software detects a specific error but takes no actions to handle the error.[16]',
            mitigation:'Properly handle each exception. This is the recommended solution. Ensure that all exceptions are handled in such a way that you can be sure of the state of your system at any given moment.If a function returns an error, it is important to either fix the problem and try again, alert the user that an error has happened and let the program continue, or alert the user and close and cleanup the program. When testing subject, the software to extensive testing to discover some of the possible instances of where/how errors or return values are not handled.Consider testing techniques such as ad hoc,equivalence partitioning, robustness and fault tolerance, mutation, and fuzzing.[16]',
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

    flow.rule('Missing Error Handling',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type ==  "tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "python, java, objectivec, c#, c++, c")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '5.3',
            title:'Missing Error Handling',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'A web application must define a default error page for 404 errors, 500 errors, and to catch java.lang.Throwable exceptions prevent attackers from mining information from the application container\'s built-in error response. When an attacker explores a web site looking for vulnerabilities, the amount of information that the site provides is crucial to the eventual success or failure of any attempted attacks. If the application shows the attacker a stack trace, it gives information that makes the attacker\'s job significantly easier. For example, a stack trace might show the attacker a malformed SQL query string,the type of database being used, and the version of the application container. This information enables the attacker to target known vulnerabilities in these components.',
            mitigation:'The application configuration should specify a default error page in order to guarantee that the application will never leak error messages to an attacker. Handling standard HTTP error codes is useful and user-friendly in addition to being a good security practice, and a good configuration will also define a last-chance error handler that catches any exception that could possibly be thrown by the application.A specific policy for how to handle errors should be documented, including the types of errors tobe handled and for each, what information is going to be reported back to the user, and what information is going to be logged. All developers need to understand the policy and ensure that their code follows it. When errors occur, the site should respond with a specifically designed result that is helpful to the user without revealing unnecessary internal details.Certain classes of errors should be logged to help detect implementation flaws in the site and/or hacking attempts. Very few sites have any intrusion detection capabilities in their web application, but it is certainly conceivable that a web application could track repeated failed attempts and generate alerts.',
            references:[{name:'Missing Error Handling', link:'https://www.owasp.org/index.php/Missing_Error_Handling'},{name:'Improper Error Handling', link:'https://www.owasp.org/index.php/Improper_Error_Handling'}],
            examples:[
                {
                    preText: 'An "HTTP 404 - File not found" error tells an attacker that the requested file doesn\'t exist rather than that he doesn\'t have access to the file. This can help the attacker to decide his next step.',
                }
            ]
        });});

    flow.rule('Return Inside Finally Block', {scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type ==  "tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "python, java, objectivec, c#, c++, c")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '5.4',
            title:'Return Inside Finally Block',
            type:'Denial of service',
            status:'Open',
            severity:'Low',
            description:'The code has a return statement inside a finally block, which will cause any thrown exception in the try block to be discarded.',
            mitigation:'Do not use a return statement inside the finally block. The finally block should have \"cleanup\"code.',
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

    flow.rule('Unchecked Error Condition',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type ==  "tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "python, java, objectivec, c#, c++, c"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "python, java, objectivec, c#, c++, c")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '5.5',
            title:'Unchecked Error Condition',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'Ignoring exceptions and other error conditions may allow an attacker to induce unexpected behavior unnoticed.',
            mitigation:'The choice between a language which has named,or unnamed exceptions needs to be done. While unnamed exceptions exacerbate the chance of not properly dealing with an exception, named exceptions suffer from the up-call version of the weak base class problem.A language can be used which requires, at compile time, to catch all serious exceptions. However, one must make sure to use the most current version of the API as new exceptions could be added.Catch all relevant exceptions. This is the recommended solution. Ensure that all exceptions are handled in such a way that you can be sure ofthe state of your system at any given moment.[21]',
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

    flow.rule('Deserialization of Untrusted Data',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.isEncryptedProcess) && isFalse(el.element.validatesInputProcess)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore) && isFalse(el.element.validatesInputStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.isEncryptedMobilePhone) && isFalse(el.element.validatesInputMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.isEncryptedSmartWatch) && isFalse(el.element.validatesInputSmartWatch)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.isEncryptedLaptop) && isFalse(el.element.validatesInputLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.isEncryptedTablet) && isFalse(el.element.validatesInputTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.isEncryptedElectrocardiogram) && isFalse(el.element.validatesInputElectrocardiogram))|| (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.isEncryptedPacemaker) && isFalse(el.element.validatesInputPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.1',
            title:'Deserialization of Untrusted Data',
            type:'Denial of service',
            status:'Open',
            severity:'Medium',
            description:'The application de serializes untrusted data without sufficiently verifying that the resulting data will be valid. It is often convenient to serialize objects for communication or to save them for later use. However, de serialized data or code can often be modified without using the provided accessor functions if it does not use cryptography to protect itself.',
            mitigation:'If available, use the signing/sealing features of the programming language to assure that de serialized data has not been tainted. For example, a hash-based message authentication code (HMAC)could be used to ensure that data has not been modified.When de serializing data, populate a new object rather than just de serializing. The result is that the data flows through safe input validation and that the functions are safe. Explicitly define a final object() to prevent de serialization. Make fields transient to protect them from de serialization. An attempt to serialize and then de serialize a class containing transient fields will result in NULLs where the transient data should be. Avoid having unnecessary types or gadgets available that can be leveraged for malicious ends. This limits the potential for unintended or unauthorized types and gadgets to be leveraged by the attacker. Whitelist acceptable classes. NOTE: This is alone is not a sufficient mitigation.',
            references:[{name:'CWE-502: Deserialization of Untrusted Data', link:'https://cwe.mitre.org/data/definitions/502.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'This code snippet de serializes an object from a file and uses it as a UI button:',
                    postText: 'This code does not attempt to verify the source or contents of the file before de serializing it. An attacker may be able to replace the intended file with a file that contains arbitrary malicious code which will be executed when the button is pressed.',
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
                        'throw new java.io.IOException("Cannot be de serialized"); }'
                },
                {
                    language: {name: 'Python', highlightAlias: 'python'},
                    preText: 'In Python, the Pickle library handles the serialization and deserialization processes. The code below receives and parses data, and afterwards tries to authenticate a user based on validating a token.',
                    postText: 'Unfortunately, the code does not verify that the incoming data is legitimate. An attacker can construct a illegitimate, serialized object "AuthToken" that instantiates one of Python\'s sub processes to execute arbitrary commands. For instance, the attacker could construct a pickle that leverages Python\'s sub process module, which spawns new processes and includes a number of arguments for various uses. Since Pickle allows objects to define the process for how they should be un pickled, the attacker can direct the un pickle process to call Popen in the sub process module and execute /bin/sh.',
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

    flow.rule('Expression Language Injection',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","jsp, juel, spring"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "jsp, juel, spring"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "jsp, juel, spring"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","jsp, juel, spring"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "jsp, juel, spring"))) || (el.element.attributes.type ==  "tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "jsp, juel, spring"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "jsp, juel, spring")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.2',
            title:'Expression Language Injection',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'Server-side code injection vulnerabilities arise when an application incorporates user-controllable data into a string that is dynamically evaluated by a code interpreter. If the user data is not strictly validated,an attacker can use crafted input to modify the code to be executed and inject arbitrary code that will be executed by the server. Server-side code injection vulnerabilities are usually very serious and lead to complete compromise of the application\'sdata and functionality, and often of the server that is hosting the application. It may also be possible to use the server as a platform for further attacks against other systems.',
            mitigation:'Whenever possible, applications should avoid incorporating user-controllable data into dynamically evaluated code. In almost every situation, there are safer alternative methods of implementing application functions, which cannot be manipulated to inject arbitrary code into the server\'s processing.If it is considered unavoidable to incorporate user-supplied data into dynamically evaluated code, then the data should be strictly validated. Ideally, a whitelist of specific accepted values should be used. Otherwise, only short alphanumeric strings should be accepted. Input containing any other data,including any conceivable code metacharacters,should be rejected.',
            references:[{name:'Expression Language injection', link:'https://portswigger.net/kb/issues/00100f20_expression-language-injection'}]});});

    flow.rule('Form Action Hijacking',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","html"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "html"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "html"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","html"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "html"))) || (el.element.attributes.type ==  "tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "html"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "html")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.3',
            title:'Form Action Hijacking',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'Form action hijacking vulnerabilities arise when an application places user-supplied input into the action URL of an HTML form. An attacker can use this vulnerability to construct a URL that, if visited by another application user, will modify the actionURL of a form to point to the attacker\'s server. If a user submits the form then its contents, including any input from the victim user, will be delivered directly to the attacker. Even if the user doesn\'t enter any sensitive information, the form may still deliver a valid CSRF token to the attacker, enabling them to perform CSRF attacks. In some cases, web browsers may help exacerbate this issue by autocompleting forms with previously entered user input.',
            mitigation:'Consider hard-coding the form action URL or implementing a whitelist of allowed values.',
            references:[{name:'Form action hijacking (reflected)', link:'https://portswigger.net/kb/issues/00501500_form-action-hijacking-reflected'}]});});

    flow.rule('Improper Input Validation',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.validatesInputProcess)) ||(el.element.attributes.type == "tm.Store" && isFalse(el.element.validatesInputStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isFalse(el.element.validatesInputMobilePhone))|| (el.element.attributes.type == "tm.SmartWatch" && isFalse(el.element.validatesInputSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isFalse(el.element.validatesInputLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isFalse(el.element.validatesInputTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isFalse(el.element.validatesInputElectrocardiogram))|| (el.element.attributes.type == "tm.Pacemaker" && isFalse(el.element.validatesInputPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.4',
            title:'Improper Input Validation',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program. When software does not validate input properly, an attacker is able to craft the input in a form that is not expected by the rest of the application. This will lead to parts of the system receiving unintended input, which may result in altered control flow, arbitrary control of a resource, or arbitrary code execution.',
            mitigation:'Use an input validation framework such asStruts or the OWASP ESAPI ValidationAPI. If you use Struts, be mindful ofStruts Validation ProblemsUnderstand all the potential areas where untrusted inputs can enter your software:parameters or arguments, cookies,anything read from the network,environment variables, reverse DNS lookups, query results, request headers,URL components, e-mail, files, filenames,databases, and any external systems that provide data to the application.Remember that such inputs may be obtained indirectly through API calls.Assume all input is malicious. Use an\"accept known good\" input validation strategy, i.e., use a whitelist of acceptable inputs that strictly conform to specifications. Reject any input that does not strictly conform to specifications or transform it into something that does.When performing input validation,consider all potentially relevant properties, including length, type of input,the full range of acceptable values,missing or extra inputs, syntax,consistency across related fields, and conformance to business rules. As an example of business rule logic, \"boat\"may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as \"red\" or \"blue.\"Do not rely exclusively on looking for malicious or malformed inputs (i.e., do not rely on a blacklist). A blacklist is likely to miss at least one undesirable input, especially if the code\'s environment changes. This can give attackers enough room to bypass the intended validation. However, blacklists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright.For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid client-side enforcement of server-side security, Attackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely. Then, these modified values would be submitted to the server.Use dynamic tools and techniques that interact with the software using large test suites with many diverse inputs, such as fuzz testing (fuzzing), robustness testing, and fault injection. Use tools and techniques that require manual (human) analysis, such as penetration testing, threat modeling, and interactive tools that allow the tester torecord and modify an active session[25]',
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
            description:'The software accepts XML from an untrusted source but does not validate the XML against the proper schema. Most successful attacks begin with a violation of the programmer\'s assumptions. By accepting an XML document without validating it against a DTD or XML schema, the programmer leaves a door open for attackers to provide unexpected,unreasonable, or malicious input.[36]',
            mitigation:'Always validate XML input against a known XML Schema or DTD.It is not possible for an XML parser to validate all aspects of a document\'scontent because a parser cannot understand the complete semantics of the data. However, a parser can do a complete and thorough job of checking the document\'s structure and therefore guarantee to the code that processes the document that the content is well-formed.A XML validator should be used to check to check the schema of the XML file. A suggested validator that can be used is found at this website :https://www.freeformatter.com/xml-validator-xsd.html',
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

    flow.rule('Overly Permissive Regular Expression',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.userInputProcess)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.userInputStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.userInputMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.userInputSmartWatch)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.userInputTablet)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.userInputLaptop)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.userInputElectrocardiogram)) ||(el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.userInputPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.6',
            title:'Overly Permissive Regular Expression',
            type:'Elevation of privilege',
            status:'Open',
            severity:'High',
            description:'The product uses a regular expression that does not sufficiently restrict the set of allowed values.',
            mitigation:'To mitigate this threat, where possible, ensure that the regular expressions does a check to see where the start and end string patterns are. As well there should be a restriction to limit the number of characters in a given string that the regular expression will check.',
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
            description:'Executing commands or loading libraries from an untrusted source or in an untrusted environment can cause an application to execute malicious commands (and payloads) on behalf of an attacker. Process control vulnerabilities take two forms: An attacker can change the command that the program executes by explicitly controlling what the command is. An attacker can change the environment in which the command executes by implicitly controlling what the command means. Process control vulnerabilities of the first type occur when either data enters the application from an untrusted source and the data is used as part of a string representing a command that is executed by the application. By executing the command, the application gives an attacker a privilege or capability that the attacker would not otherwise have.',
            mitigation:'Libraries that are loaded should be well understood and come from a trusted source. The application can execute code contained in the native libraries, which often contain calls that are susceptible to other security problems, such as buffer overflows or command injection. All native libraries should be validated to determine if the application requires the use of the library. It is very difficult to determine what these native libraries do,and the potential for malicious code is high. In addition, the potential for an inadvertent mistake in these native libraries is also high, as many are written in C or C++ and may be susceptible to buffer overflow or race condition problems. To help prevent buffer overflow attacks, validate all input to native calls for content and length. If the native library does not come from a trusted source, review the source code of the library. The library should be built from the reviewed source before using it.',
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

    flow.rule('String Termination Error',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","c, c++, assembly"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "c, c++, assembly"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "c, c++, assembly"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","c, c++, assembly"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "c,c++, assembly"))) || (el.element.attributes.type ==  "tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "c, c++, assembly"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "c, c++, assembly")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.8',
            title:'String Termination Error',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'Relying on proper string termination may result in a buffer overflow.String termination errors occur when:Data enters a program via a function that does not null terminate its output. The data is passed to a function that requires its input to be null terminated.',
            mitigation:'Use a language that is not susceptible to these issues. However, be careful of null byte interaction errors with lower-level constructs that may be written in a language that is susceptible.Ensure that all string functions used are understood fully as to how they append null characters. Also, be wary of off-by-one errors when appending nulls to the end of strings.If performance constraints permit, special code can be added that validates null-termination of string buffers, this is a rather naive and error-prone solution.Switch to bounded string manipulation functions. Inspect buffer lengths involved in the buffer overrun trace reported with the defect.Add code that fills buffers with nulls (however, the length of buffers still needs to be inspected, to ensure that the non-null-terminated string is not written at the physical end of the buffer).Visit the following pages for more information for mitigation strategies for strings in C and C++:http://www.informit.com/articles/article.aspx?p=2036582&seqNum=4https://www.synopsys.com/blogs/software-security/detect-prevent-and-mitigate-buffer-overflow-attacks/[41]',
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

    flow.rule('Unchecked Return Value',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type == "tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type == "tm.SmartWatch") || (el.element.attributes.type == "tm.Laptop") || (el.element.attributes.type == "tm.Tablet") || (el.element.attributes.type == "tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.9',
            title:'Unchecked Return Value',
            type:'Tampering',
            status:'Open',
            severity:'Low',
            description:'The software does not check the return value from a method or function, which can prevent it from detecting unexpected states and conditions. Two common programmer assumptions are \"this function call can never fail\" and \"it doesn\'t matter if this function call fails\". If an attacker can force the function to fail or otherwise return a value that is not expected, then the subsequent program logic could lead to a vulnerability, because the software is not in a state that the programmer assumes. For example, if the program calls a function to drop privileges but does not check the return code to ensure that privileges were successfully dropped, then the program will continue to operate with the higher privileges.',
            mitigation:'To mitigate this threat, three techniques must be applied to all functions in the given program that is being evaluated: Ensure all of the functions that return a value,actually return a value and confirm that the value is expected.Ensure within each function, that the possible of return values are coveredWithin each function, ensure that there is a check/default value when there is an error. [40]',
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

    flow.rule('Unsafe JNI',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","java"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "java"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "java"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","java"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "java"))) || (el.element.attributes.type ==  "tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "java"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "java")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.10',
            title:'Unsafe JNI',
            type:'Denial of service',
            status:'Open',
            severity:'Low',
            description:'When a Java application uses the Java NativeInterface (JNI) to call code written in another programming language, it can expose the application to weaknesses in that code, even if those weaknesses cannot occur in Java. Many safety features that programmers may take for granted simply do not apply for native code, so you must carefully review all such code for potential problems. The languages used to implement native code may be more susceptible to buffer overflows and other attacks. Native code is unprotected by the security features enforced by the runtime environment, such as strong typing and array bounds checking',
            mitigation:'To mitigate this threat, three techniques must be applied in the given program that is being evaluated: Implement a form of error handling within each JNIcall. Avoid using any JNI calls if the native library is untrusted.Seek an alternative to a JNI call such as using a JavaAPI.',
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

    flow.rule('Unsafe use of reflection',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.Process"  && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageProcess","c#, python, ruby, java, php"))) || (el.element.attributes.type == "tm.MobilePhone" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageMobilePhone", "c#, python, ruby, java, php"))) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageSmartWatch", "c#, python, ruby, java, php"))) || (el.element.attributes.type == "tm.Laptop" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageLaptop","c#, python, ruby, java, php"))) || (el.element.attributes.type == "tm.Tablet" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageTablet", "c#, python, ruby, java, php"))) || (el.element.attributes.type ==  "tm.Electrocardiogram" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguageElectrocardiogram", "c#, python, ruby, java, php"))) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(dropDownOptionsCheck("checkboxProgrammingLanguagePacemaker", "c#, python, ruby, java, php")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '6.11',
            title:'Unsafe use of reflection',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'This vulnerability is caused by unsafe use of the reflection mechanisms in programming languages like Java, C#, or Ruby, etc. An attacker may be able to create unexpected control flow paths through the application, potentially bypassing security checks. Exploitation of this weakness can result in a limited form of code injection. If an attacker can supply values that the application then uses to determine which class to instantiate or which method to invoke, the potential exists for the attacker to create control flow paths through the application that were not intended by the application developers. This attack vector may allow the attacker to bypass authentication or access control checks or otherwise cause the application to behave in an unexpected manner. This situation becomes a doomsday scenario if the attacker can upload files into a location that appears on the application\'s classpath or add new entries to the application\'s classpath. Under either of these conditions, the attacker can use reflection to introduce new, presumably malicious, behavior into the application.',
            mitigation:'Refactor your code to avoid using reflection.Do not use user-controlled inputs to select and load classes or code. Apply strict input validation by using whitelists or indirect selection to ensure that the user is only selecting allowable classes or code.',
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
            description:'An adversary that has attained a lost/stolen mobile device; malware or another repackaged app acting on the adversary\'s behalf that executes on the mobile device. If an adversary physically attains the mobile device, the adversary hooks up the mobiledevice to a computer with freely available software. These tools allow the adversary to see all third party application directories that often contain stored personally identifiable information (PII), or Personal Health Records (PHR). An adversary may construct malware or modify a legitimate app to steal such information assets.',
            mitigation:'It is important to threat model your mobile app, OS,platforms and frameworks to understand the information assets the app processes and how the APIs handle those assets. Determine how your application or software handles the following information: URL caching (both request and response);Keyboard press caching;Copy/Paste buffer caching;Application backgrounding; Intermediate dataLogging; HTML5 data storage; Browser cookie objects; Analytics data sent to 3rd parties.',
            references:[{name:'Insecure Data Storage', link:'https://www.owasp.org/index.php/Mobile_Top_10_2016-M2-Insecure_Data_Storage'}]});});

    flow.rule('Improper Platform Usage',[[Element, 'el','(el.element.attributes.type == "tm.MobilePhone")|| (el.element.attributes.type == "tm.SmartWatch")|| (el.element.attributes.type == "tm.Tablet")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.2',
            title:'Improper Platform Usage',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'This category covers misuse of a platform feature or failure to use platform security controls. It might include Android intents, platform permissions,misuse of TouchID, the Keychain, or some other security control that is part of the mobile operating system. The defining characteristic of risks in this category is that the platform (iOS, Android)provides a feature or a capability that is documented and well understood. The app fails to use that capability or uses it incorrectly. This differs from other mobile top ten risks because the design and implementation is not strictly the app developer\'s issue.There are several ways that mobile apps can experience this risk.Violation of published guidelines. All platforms have development guidelines for security (((Android)),((iOS))). If an app contradicts the best practices recommended by the manufacturer, it will be exposed to this risk. For example, there are guidelines on how to use the iOS Keychain or how to secure exported services on Android. Apps that do not follow these guidelines will experience this risk. Violation of convention or common practice: Not all best practices are codified in manufacturer guidance. In some instances, there are de facto best practices that are common in mobile apps. Unintentional Misuse: Some apps intend to do the right thing but get some part of the implementation wrong. This could be a simple bug, like setting the wrong flag on an API call, or it could be a misunderstanding of how the protections work.',
            mitigation:'To mitigate this threat, secure coding and proper configurations must be used on the server side of the mobile application [47].',
            references:[{name:'Improper Platform Usage', link:'https://www.owasp.org/index.php/Mobile_Top_10_2016-M1-Improper_Platform_Usage'}]});});

    flow.rule('Insecure Communication',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow) && isFalse(el.element.isPublicNetwork)) ||(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow) && isFalse(el.element.wifiInterface)) ||(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow) && isFalse(el.element.bluetoothInterface)) ||(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow) && isFalse(el.element.cellularInterface))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.3',
            title:'Insecure Communication',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'When designing a mobile application, data is commonly exchanged in a client-server fashion.When the solution transmits its data, it must traverse the mobile device\'s carrier network and the internet. Attackers may exploit these vulnerabilities to intercept sensitive data such as:social security numbers, web surfing history, credit card numbers, bank accounts, personal health records such as medical conditions, insurance information, prescription records, medical histories,test and laboratory result while travelling across the wire.',
            mitigation:'Assume that the network layer is not secure and is susceptible to eavesdropping. Apply SSL/TLS to transport channels that the mobile app will use to transmit sensitive information,session tokens, or other sensitive data to a backendAPI or web service.Account for outside entities like third-party analytics companies, social networks, etc. by using their SSL versions when an application runs a routine via the browser/webkit. Avoid mixed SSL sessions as they may expose the user\'s session ID.Use strong, industry standard cipher suites with appropriate key lengths.Use certificates signed by a trusted CA provider.Never allow self-signed certificates and consider certificate pinning for security conscious applications. Always require SSL chain verification. Only establish a secure connection after verifying the identity of the endpoint server using trusted certificates in the key chain.Alert users through the UI if the mobile app detects an invalid certificate. Do not send sensitive data over alternate channels (e.g. SMS, MMS, or notifications). If possible, apply a separate layer of encryption to any sensitive data before it is given to the SSL channel. If future vulnerabilities are discovered in the SSL implementation, the encrypted data will provide a secondary defense against confidentiality violation.',
            references:[{name:'Insecure Communication', link:'https://www.owasp.org/index.php/Mobile_Top_10_2016-M3-Insecure_Communication'}]});});

    flow.rule('Insecure Authentication',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.providesAuthenticationMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.providesAuthenticationLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram))|| (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.4',
            title:'Insecure Authentication',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'Authentication vulnerabilities are exploited through automated attacks that use available or custom-built tools.Once the adversary understands how the authentication scheme is vulnerable, they fake or bypass authentication by submitting service requests to the mobile app\'s backend server and bypass any direct interaction with the mobile app.This submission process is typically done via mobile malware within the device or botnets owned by the attacker.',
            mitigation:'Avoid weak authentication patterns:If you are porting a web application to its mobile equivalent,authentication requirements of mobile applications should match that of the web application component. Therefore, it should not be possible to authenticate with less authentication factors than the web browser.Authenticating a user locally can lead to client-side bypass vulnerabilities. If the application stores data locally, the authentication routine can be bypassed on jailbroken devices through run-time manipulation or modification of the binary.If there is a compelling business requirement for offline authentication, see M10 for additional guidance on preventing binary attacks against the mobile app; Where possible, ensure that all authentication requests are performed server-side. Upon successful authentication,application data will be loaded onto the mobile device. This will ensure that application data will only be available after successful authentication;If client-side storage of data is required, the data will need tobe encrypted using an encryption key that is securely derived from the user\'s login credentials. This will ensure that the stored application data will only be accessible upon successfully entering the correct credentials. There are additional risks that the data will be decrypted via binary attacks. See M9 for additional guidance on preventing binary attacks that lead to local data theft; Persistent authentication (Remember Me) functionality implemented within mobile applications should never store a user\'s password on the device;Ideally, mobile applications should utilize a device-specific authentication token that can be revoked within the mobile application by the user. This will ensure that the app can mitigate unauthorized access from a stolen/lost device; Do not use any spoof-able values for authenticating a user. This includes device identifiers or geo-location; Persistent authentication within mobile applications should be implemented as opt-in and not be enabled by default; If possible, do not allow users to provide 4-digit PIN numbers for authentication passwords. Reinforce Authentication: Developers should assume all client-side authorization and authentication controls can be bypassed by malicious users. Authorization and authentication controls must be re-enforced on the server-side whenever possible. Due to offline usage requirements, mobile apps may be required to perform local authentication or authorization checks within the mobile app\'s code. If this is the case, developers should instrument local integrity checks within their code to detect any unauthorized code changes. See M9for more information about detecting and reacting to binaryattacks.[49]',
            references:[{name:'Insecure Authentication', link:'https://www.owasp.org/index.php/Mobile_Top_10_2016-M4-Insecure_Authentication [51] https://www.owasp.org/index.php/Mobile_Top_10_2014-M4'}]});});

    flow.rule('Insufficient Transport Layer Protection',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncryptedFlow) && isFalse(el.element.usesTLS))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.5',
            title:'Insufficient Transport Layer Protection',
            type:'Information disclosure',
            status:'Open',
            severity:'Medium',
            description:'When designing a mobile application, data is commonly exchanged in a client-server fashion. When the solution transmits its data, it must traverse the mobile device\'s carrier network and the internet. Threat agents might exploit vulnerabilities to intercept sensitive data while it\'straveling across the wire. The following ways are possible threat agents that exist:An adversary that shares your local network(compromised or monitored Wi-Fi);Carrier or network devices (routers, cell towers,proxy\'s, etc.); or Malware on your mobile device.',
            mitigation:'General Best Practices:Assume that the network layer is not secure and is susceptible to eavesdropping.Apply SSL/TLS to transport channels that the mobile app will use to transmit sensitive information, session tokens, or other sensitive data to a backend API or web service.Account for outside entities like third-party analytics companies, social networks, etc. by using their SSL versions when an application runs a routine via the browser\'s webkit. Avoid mixed SSL sessions as they may expose the user\'s session ID.Use strong, industry standard cipher suites with appropriate key lengths.Use certificates signed by a trusted CA provider.Never allow self-signed certificates and consider certificate pinning for security conscious applications. Always require SSL chain verification. Only establish a secure connection after verifying the identity of the endpoint server using trusted certificates in the key chain. Alert users through the UI if the mobile app detects an invalid certificate. Do not send sensitive data over alternate channels(e.g, SMS, MMS, or notifications).If possible, apply a separate layer of encryption to any sensitive data before it is given to the SSL channel. In the event that future vulnerabilities are discovered in the SSL implementation, the encrypted data will provide a secondary defense against confidentiality violation.iOS Specific Best Practices:Default classes in the latest version of iOS handleSSL cipher strength negotiation very well. Trouble comes when developers temporarily add code to bypass these defaults to accommodate development hurdles. In addition to the above general practices:Ensure that certificates are valid and fail closed.When using CFNetwork, consider using the SecureTransport API to designate trusted client certificates. In almost all situations,NSStreamSocketSecurityLevelTLSv1 should be used for higher standard cipher strength. After development, ensure all NSURL calls (orwrappers of NSURL) do not allow self-signed or invalid certificates such as the NSURL class method setAllowsAnyHTTPSCertificate. Consider using certificate pinning by doing the following: export your certificate, include it in your app bundle, and anchor it to your trust object. Using the NSURL method connection:willSendRequestForAuthenticationChallenge: will now accept your cert.Android Specific Best Practices:Remove all code after the development cycle that may allow the application to accept all certificates such as org.apache.http.conn.ssl.AllowAllHostnameVerifier or SSLSocketFactory.ALLOW_ALL_HOSTNAME_VERIFIER. These are equivalent to trusting all certificates. If using a class which extends SSLSocketFactory, make sure checkServerTrusted method is properly implemented so that server certificate is correctly checked.',
            references:[]});});

    flow.rule('Unintended Data Leakage',[[Element, 'el','(el.element.attributes.type == "tm.Store")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.6',
            title:'Unintended Data Leakage',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'Unintended data leakage occurs when a developer inadvertently places sensitive information or data ina location on the mobile device that is easily accessible by other apps on the device. This vulnerability is exploited by mobile malware, modified versions of legitimate apps, or an adversary that has physical access to the victim\'smobile device. In case the attacker has physical access to the device, then the attacker can use freely available forensic tools to conduct an attack.Another possible attack vector would be if an attacker has access to the device via malicious code, so they will use fully permissible and documentedAPI calls to conduct an attack. [51]',
            mitigation:'Threat model your OS, platforms, and frameworks to determine how they handle the following features: URL Caching (Both request and response), Keyboard Press Caching, Copy/Paste buffer, CachingApplication, backgrounding, Logging, HTML5 data storageBrowser cookie objects Analytics data sent to 3rd partiesAlso identify what a given OS or framework does by default, by doing this and applying mitigating controls, unintended data leakage can be avoided.',
            references:[]});});

    flow.rule('Broken/Insecure Cryptography',{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},[[Element, 'el','(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.isEncryptedMobilePhone)&& isTrue(dropDownOptionsCheck("encryptionTypeForMobilePhone", "des, rsa, tripleDes,tripleDes3Key, rc2, rc4, 128rc4, desx")))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.7',
            title:'Broken/Insecure Cryptography',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'This threat is cause when an adversary has physical access to data that has been encrypted improperly,or mobile malware acting on an adversary\'s behalf.This can be done in several ways such as decryption access to the device or network traffic capture, or malicious apps on the device with access to the encrypted data.',
            mitigation:'To mitigate this threat, avoid using algorithms or protocols that are unsecure such as \'RC2\',\'MD4\', \'MD5\' and \'SHA1\'. A stronger cryptographic algorithm that is widely known to be secure should be used. Currently, AES is one of the most secure encryption algorithms and is recommended to be used.',
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

    flow.rule('Client-Side Injection',[[Element, 'el','(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.userInputMobilePhone) && isTrue(el.element.validatesInputMobilePhone))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.8',
            title:'Client-Side Injection',
            type:'Information disclosure',
            status:'Open',
            severity:'Medium',
            description:'Client-side injection results in the execution of malicious code on the mobile device via the mobile app. Consider anyone who can send untrusted data to the mobile app, including external users, internal users, the application itself or other malicious apps on the mobile device. A possible attack vector could be an adversary loads simple text-based attacks that exploit the syntax of the targeted interpreter within the mobile app. It is important to understand that almost any source of data can be an injection vector, including resource files or the application itself.',
            mitigation:'IOS Specific Best Practices:SQLite Injection: When designing queries for SQLite be sure that user supplied data is being passed to a parameterized query. This can be spotted by looking for the format specifier used. In general,dangerous user supplied data will be inserted by a%@ instead of a proper parameterized query specifier.JavaScript Injection (XSS, etc): Ensure that allUIWebView calls do not execute without proper input validation. Apply filters for dangerousJavaScript characters if possible, using a whitelist over blacklist character policy before rendering. If possible, call mobile Safari instead of rending inside of UIWebkit which has access to your application.Local File Inclusion: Use input validation forNSFileManager calls.XML Injection: use libXML2 over NSXMLParserFormat String Injection: Several Objective C methods are vulnerable to format string attacks: NSLog, [NSString stringWithFormat:], [NSStringinitWithFormat:], [NSMutableStringappendFormat:], [NSAlertinformativeTextWithFormat:], [NSPredicatepredicateWithFormat:], [NSException format:],NSRunAlertPanel.Do not let sources outside of your control, such as user data and messages from other applications or web services, control any part of your format strings. Classic C Attacks: Objective C is a superset of C,avoid using old C functions vulnerable to injection such as: strcat, strcpy, strncat, strncpy, sprint,vsprintf, gets, etc.Android Specific Best Practices:SQL Injection: When dealing with dynamic queries or Content-Providers ensure you are using parameterized queries.JavaScript Injection (XSS): Verify that JavaScript andPlugin support is disabled for any WebViews(usually the default).Local File Inclusion: Verify that File System Access is disabled for any WebViews(webview.getSettings().setAllowFileAccess(false);).Intent Injection\/Fuzzing: Verify actions and data are validated via an Intent Filter for all Activities.Binary Injection\/Modification Prevention forAndroid and iOS:Follow security coding techniques for jailbreak detection, checksum, certificate pinning, and debugger detection controls. The organization building the app must adequately prevent an adversary from analyzing and reverse engineering the app using static or dynamic analysis techniques. The mobile app must be able to detect at runtime that code has been added or changed from what it knows about its integrity at compile time. The app must be able to react appropriately at runtime to a code integrity violation.',
            references:[{name:'Client Side Injection', link:'https://www.owasp.org/index.php/Mobile_Top_10_2014-M7'}]});});

    flow.rule('Poor Client Code Quality',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type == "tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type == "tm.SmartWatch") || (el.element.attributes.type == "tm.Laptop") || (el.element.attributes.type == "tm.Tablet") || (el.element.attributes.type == "tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.9',
            title:'Poor Client Code Quality',
            type:'Spoofing',
            status:'Open',
            severity:'Medium',
            description:'This threat involves entities that can pass untrusted inputs to method calls made within mobile code.These types of issues are not necessarily security issues in and of themselves but lead to security vulnerabilities. For example, buffer overflows within older versions of Safari (a poor code quality vulnerability) led to high risk drive-by Jailbreak attacks. Poor code-quality issues are typically exploited via malware or phishing scams. An attacker will typically exploit vulnerabilities in this category by supplying carefully crafted inputs to the victim. These inputs are passed onto code that resides within the mobile device where exploitation takes place. Typical types of attacks will exploit memory leaks and buffer overflows.[54]',
            mitigation:'To mitigate this threat, the following countermeasures should be considered:Consistent coding patterns, standards in an organizationWrite code that is legible and documentedAny code that requires a buffer, the length of the input should be checked, and the length should be restricted. Use third party tools to find buffer overflows and memory leaks.Prioritize to fix any buffer overflows and memory leaks that are present in the code before moving onto other issues.',
            references:[{name:'Poor Client Code Quality', link:'https://www.owasp.org/index.php/Mobile_Top_10_2016-M7-Poor_Code_Quality'}],
            examples:[
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'Buffer Overflow example:',
                    postText: 'We should avoid the use of the gets function to avoid a buffer overflow. This is an example of what most static analysis tools will report as a code quality issue.',
                    code: 'include <stdio.h>\n' +
                        '\n' +
                        ' int main(int argc, char **argv)\n' +
                        '    {\n' +
                        '    char buf[8]; // buffer for eight characters\n' +
                        '    gets(buf); // read from stdio (sensitive function!)\n' +
                        '    printf("%s\\n", buf); // print out data stored in buf\n' +
                        '    return 0; // 0 as return value\n' +
                        '    }'
                }
            ]
        });});

    flow.rule('Security Decisions Via Untrusted Inputs',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type == "tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type == "tm.SmartWatch") || (el.element.attributes.type == "tm.Laptop") || (el.element.attributes.type == "tm.Tablet") || (el.element.attributes.type == "tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.10',
            title:'Security Decisions Via Untrusted Inputs',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'This threat involves entities that can pass untrusted inputs to the sensitive method calls. Examples of such entities include, but are not limited to, users, malware and vulnerable apps  An attacker with access to app can intercept intermediate calls and manipulate results via parameter tampering.',
            mitigation:'To mitigate this threat, avoid using depreciated/unsupported methods for each platform that the application is being used. As an example, for iOS, avoid using the handleOpenURLmethod to process URL scheme calls. Find an alternative method that is supported by the platform.',
            references:[{name:'Security Decisions via Untrusted Inputs', link:'https://www.owasp.org/index.php/Mobile_Top_10_2014-M8'}]});});

    flow.rule('Improper Session Handling',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.isAWebApplication))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.11',
            title:'Improper Session Handling',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'Anyone or any mobile app with access to HTTP/S traffic, cookie data, etc.  Possible attack vectors include physical access to the device, and network traffic capture, or malware on the mobile device. Essentially an adversary that has access to the session tokens can impersonate the user by submitting the token to the backend server for any sensitive transactions such as credit card payments or health information like EKG results sent to a doctor.',
            mitigation:'Validate sessions on the backend by ensuring all session invalidation events are executed on the server side and not just on the mobile app.Add adequate timeout protection to prevent the malicious potential for an unauthorized user to gain access to an existing session and assume the role of that user. Timeout periods vary accordingly based on the application, but some good guidelines are: 15 minutes for high security apps, 30 minutes for medium security apps, and 1hour for low security apps.Properly reset cookies during authentication state changes, by destroying sessions on the server side and making sure that the cookies presented as a part of the previous sessions are no longer acceptedIn addition to properly invalidating tokens on the server side during key application events, make sure tokens are generated properly by using well-established and industry standard methods of creating tokens. Visit the following websites for more details:https://www.pcisecuritystandards.org/documents/Tokenization_Product_Security_Guidelines.pdf, https:/ools.ietf.org/html/rfc7519 for JSONWeb Token (JWT) and https://www.ietf.org/rfc/rfc6750.txt for BearerToken Usage',
            references:[{name:'Improper Session Handling', link:'https://www.owasp.org/index.php/Mobile_Top_10_2014-M9'}]});});

    flow.rule('Lack of Binary Protections',[[Element, 'el','(el.element.attributes.type == "tm.MobilePhone")|| (el.element.attributes.type == "tm.Tablet") ||(el.element.attributes.type == "tm.SmartWatch")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '7.12',
            title:'Lack of Binary Protections',
            type:'Information disclosure',
            status:'Open',
            severity:'High',
            description:'This threat involves an adversary who will analyze and reverse engineer a mobile app\'s code, then modify it to perform some hidden functionality. The majority of mobile apps do not prevent an adversary from successfully analyzing, reverse engineering or modifying the app\'s binary code.[60]',
            mitigation:'To mitigate this threat from an adversary from analysis and reversing engineering the code, or unauthorized code modification, an application must follow very secure guidelines to activate the following mechanisms in a platform:Jailbreak Detection Controls;Checksum Controls;Certificate Pinning Controls;Debugger Detection ControlsThese controls also require that the application have two more additional requirements. Firstly, the organization that is making the app must attempt to deny the adversary to analyze and reverse engineer the app using analysis techniques that can be static or dynamic. Lastly, the app must be able to determine at runtime if it\'s application code has been modified or added and react accordingly. [60]',
            references:[{name:'Lack of Binary Protections', link:'https://www.owasp.org/index.php/Mobile_Top_10_2014-M10'}]});});

    flow.rule('Improper Output Neutralization for Logs',[[Element, 'el','(el.element.attributes.type == "tm.Store" && isTrue(el.element.isALogStore))  ||(el.element.attributes.type == "tm.Process"  && isTrue(el.element.isALog)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.isALogMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.isALogSmartPhone)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.isALogLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.isALogTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.isALogElectrocardiogram)) ||(el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.isALogPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '8.1',
            title:'Improper Output Neutralization for Logs',
            type:'Repudiation',
            status:'Open',
            severity:'Medium',
            description:'The software does not neutralize or incorrectly neutralizes output that is written to logs. [61]',
            mitigation:'To mitigate this threat, there are 2countermeasures that can be implemented. Firstly,any input should be assumed to be malicious. All input should be validated, where a whitelist should be used to accept input based on specific requirements. Properties that should be considered include length, type, full range of accepted values,missing or extra input, syntax, consistency and conforming to business logic. Another countermeasure is to have the output encoded in a particular format that a downstream consumer can',
            references:[{name:'CWE-117: Improper Output Neutralization for Logs', link:'https://cwe.mitre.org/data/definitions/117.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following web application code attempts to read an integer value from a request object. If the parseInt call fails, then the input is logged with an error message indicating what happened.',
                    postText: 'If a user submits the string "twenty-one" for val, the following entry is logged:\n' +
                        '\n' +
                        'INFO: Failed to parse val=twenty-one\n' +
                        'However, if an attacker submits the string "twenty-one%0a%0aINFO:+User+logged+out%3dbadguy", the following entry is logged:\n' +
                        '\n' +
                        'INFO: Failed to parse val=twenty-one\n' +
                        'INFO: User logged out=badguy\n' +
                        'Clearly, attackers can use this same mechanism to insert arbitrary log entries.',
                    code: 'String val = request.getParameter("val");\n' +
                        'try {\n' +
                        '\n' +
                        'int value = Integer.parseInt(val);\n' +
                        '}\n' +
                        'catch (NumberFormatException) {\n' +
                        'log.info("Failed to parse val = " + val);\n' +
                        '}\n' +
                        '...'
                }
            ]
        });});

    flow.rule('Insufficient Logging ',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type == "tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type == "tm.SmartWatch") || (el.element.attributes.type == "tm.Laptop") || (el.element.attributes.type == "tm.Tablet") || (el.element.attributes.type == "tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '8.2',
            title:'Insufficient Logging ',
            type:'Repudiation',
            status:'Open',
            severity:'Medium',
            description:'When a security-critical event occurs, the software either does not record the event or omits important details about the event when logging it.',
            mitigation:'To mitigate this threat, there are 2countermeasures that can be implemented. Firstly,logging should be centralized with different levels of details. However, in a production environment there should be sufficient logging to allow system administrators to see attacks, diagnose and recover from errors.',
            references:[{name:'CWE-778: Insufficient Logging', link:'https://cwe.mitre.org/data/definitions/778.html'}],
            examples:[
                {
                    language: {name: 'Markup', highlightAlias: 'markup'},
                    preText: 'The example below shows a configuration for the service security audit feature in the Windows Communication Foundation (WCF).',
                    postText: 'The previous configuration file has effectively disabled the recording of security-critical events, which would force the administrator to look to other sources during debug or recovery efforts.',
                    code: '<system.serviceModel>\n' +
                        '<behaviors>\n' +
                        '<serviceBehaviors>\n' +
                        '<behavior name="NewBehavior">\n' +
                        '<serviceSecurityAudit auditLogLocation="Default"\n' +
                        'suppressAuditFailure="false"\n' +
                        'serviceAuthorizationAuditLevel="None"\n' +
                        'messageAuthenticationAuditLevel="None" />\n' +
                        '\n' +
                        '...\n' +
                        '</system.serviceModel>'
                },
                {
                    language: {name: 'Markup', highlightAlias: 'markup'},
                    preText: 'Logging failed authentication attempts can warn administrators of potential brute force attacks. Similarly, logging successful authentication events can provide a useful audit trail when a legitimate account is compromised. The following configuration shows appropriate settings, assuming that the site does not have excessive traffic, which could fill the logs if there are a large number of success or failure events.',
                    code: '<system.serviceModel>\n' +
                        '<behaviors>\n' +
                        '<serviceBehaviors>\n' +
                        '<behavior name="NewBehavior">\n' +
                        '<serviceSecurityAudit auditLogLocation="Default"\n' +
                        'suppressAuditFailure="false"\n' +
                        'serviceAuthorizationAuditLevel="SuccessAndFailure"\n' +
                        'messageAuthenticationAuditLevel="SuccessAndFailure" />\n' +
                        '\n' +
                        '...\n' +
                        '</system.serviceModel>'
                }
            ]
        });});

    flow.rule('Information Exposure Through Log Files',[[Element, 'el','(el.element.attributes.type == "tm.Store" && isTrue(el.element.isALogStore))  ||(el.element.attributes.type == "tm.Process"  && isTrue(el.element.isALog)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.isALogMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.isALogSmartPhone)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.isALogLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.isALogTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.isALogElectrocardiogram)) ||(el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.isALogPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '8.3',
            title:'Information Exposure Through Log Files',
            type:'Information disclosure',
            status:'Open',
            severity:'Medium',
            description:'Information written to log files can be of a sensitive nature and give valuable guidance to an attacker or expose sensitive user information.',
            mitigation:'To mitigate this threat, there are a few mitigations that can be implemented. Firstly, any sensitive/secret information should not be written into any log files. Any debug log files should be removed prior to code being deployed in a production environment. Log files should be protected from unauthorized read/write access. Configurations should be changed when an application is transitioning to a production environment.',
            references:[{name:'CWE-532: Information Exposure Through Log Files', link:'https://cwe.mitre.org/data/definitions/532.html'},{name:'CWE-779: Logging of Excessive Data', link:'https://cwe.mitre.org/data/definitions/779.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'In the following code snippet, a user\'s full name and credit card number are written to a log file.',
                    code: 'logger.info("Username: " + usernme + ", CCN: " + ccn);'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'This code stores location information about the current user:',
                    postText: 'When the application encounters an exception it will write the user object to the log. Because the user object contains location information, the user\'s location is also written to the log.',
                    code: 'locationClient = new LocationClient(this, this, this);\n' +
                        'locationClient.connect();\n' +
                        'currentUser.setLocation(locationClient.getLastLocation());\n' +
                        '... \n' +
                        '\n' +
                        'catch (Exception e) {\n' +
                        'AlertDialog.Builder builder = new AlertDialog.Builder(this);\n' +
                        'builder.setMessage("Sorry, this application has experienced an error.");\n' +
                        'AlertDialog alert = builder.create();\n' +
                        'alert.show();\n' +
                        'Log.e("ExampleActivity", "Caught exception: " + e + " While on User:" + User.toString());\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Logging of Excessive Data',[[Element, 'el','(el.element.attributes.type == "tm.Store" && isTrue(el.element.isALogStore))  ||(el.element.attributes.type == "tm.Process"  && isTrue(el.element.isALog)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.isALogMobilePhone)) ||(el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.isALogSmartPhone)) ||(el.element.attributes.type == "tm.Laptop" && isTrue(el.element.isALogLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.isALogTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.isALogElectrocardiogram)) ||(el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.isALogPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '8.4',
            title:'Logging of Excessive Data',
            type:'Repudiation',
            status:'Open',
            severity:'Low',
            description:'The software logs too much information, making log files hard to process and possibly hindering recovery efforts or forensic analysis after an attack.',
            mitigation:'To mitigate this threat, there are a few mitigations that can be implemented. Firstly, large log files should be replaced with regularly commissioned summaries. Lastly, The log file\’s size should be restricted and controlled by a system administrator.[64]',
            references:[{name:'CWE-779: Logging of Excessive Data', link:'https://cwe.mitre.org/data/definitions/779.html'}]});});

    flow.rule('Not using password aging',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.1',
            title:'Not using password aging',
            type:'Spoofing',
            status:'Open',
            severity:'Low',
            description:'If no mechanism is in place for managing password aging, users will have no incentive to update passwords in a timely manner [65]',
            mitigation:'To mitigate this threat, an algorithm that would check how old a particular password is, should be implemented and used regularly. This algorithm must notify the user when their password is old and to change the password while not allowing the user to reuse old passwords as their new password [65].',
            references:[{name:'CWE-262: Not Using Password Aging', link:'https://cwe.mitre.org/data/definitions/262.html'}],
            examples:[
                {
                    preText: 'A common example is not having a system to terminate old employee accounts.'
                },
                {
                    preText: 'Not having a system for enforcing the changing of passwords every certain period.'
                }
            ]
        });});

    flow.rule('Password Aging with Long Expiration',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.2',
            title:'Password Aging with Long Expiration',
            type:'Spoofing',
            status:'Open',
            severity:'Low',
            description:'Allowing password aging to occur unchecked can result in the possibility of diminished password integrity.',
            mitigation:'To mitigate this threat, there should be a maximum age that a password can be valid for (ex: 4 months) before the user has to change it. An algorithm should be implemented to check the password\’s age and notify users prior to expiration of that password.',
            references:[{name:'CWE-263: Password Aging with Long Expiration', link:'https://cwe.mitre.org/data/definitions/263.html'}],
            examples:[
                {
                    preText: 'A common example is not having a system to terminate old employee accounts.'
                },
                {
                    preText: 'Not having a system for enforcing the changing of passwords every certain period.'
                }
            ]
        });});

    flow.rule('Authentication Bypass Using an Alternate Path orChannel',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.3',
            title:'Authentication Bypass Using an Alternate Path orChannel',
            type:'Spoofing',
            status:'Open',
            severity:'Medium',
            description:'A product requires authentication, but the product has an alternate path or channel that does not require authentication.',
            mitigation:'To mitigate this threat, all access is suggested to go through a centralized point of access, where each access of a resource requires a check to see if the user has permission to access that resource [68].',
            references:[{name:'CWE-288: Authentication Bypass Using an Alternate Path or Channel', link:'https://cwe.mitre.org/data/definitions/288.html'}]});});

    flow.rule('Authentication Bypass by Alternate Name',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.4',
            title:'Authentication Bypass by Alternate Name',
            type:'Spoofing',
            status:'Open',
            severity:'Medium',
            description:'The software performs authentication based on the name of a resource being accessed, or the name of the actor performing the access, but it does not properly check all possible names for that resource or actor.',
            mitigation:'To mitigate this threat, avoid hardcoding names of resources that are being accessed, if they can have alternate names.',
            references:[{name:'CWE-289: Authentication Bypass by Alternate Name', link:'https://cwe.mitre.org/data/definitions/289.html'}]});});

    flow.rule('Authentication Bypass by Capture-Replay',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.5',
            title:'Authentication Bypass by Capture-Replay',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'A capture-replay flaw exists when the design of the software makes it possible for a malicious user to sniff network traffic and bypass authentication by replaying it to the server in question to the same effect as the original message (or with minor changes).',
            mitigation:'To mitigate this threat, a timestamp and or checksum with each response and check to see if it\’s an old request to stop a replay of the same authentication process.',
            references:[{name:'CWE-294: Authentication Bypass by Capture-replay', link:'https://cwe.mitre.org/data/definitions/294.html'}]});});

    flow.rule('Reflection Attack in an Authentication Protocol',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.6',
            title:'Reflection Attack in an Authentication Protocol',
            type:'Spoofing',
            status:'Open',
            severity:'Medium',
            description:'Simple authentication protocols are subject to reflection attacks if a malicious user can use the target machine to impersonate a trusted user.',
            mitigation:'To mitigate this threat, there a few mitigations that can be used. Firstly, it is recommended to have different keys for the requestor and responder of a challenge. Another suggestion is to provide different challenges for the requestor and responder. Prior to the challenge, it is recommended to have the requestor prove it\’s identity.',
            references:[{name:'CWE-301: Reflection Attack in an Authentication Protocol', link:'https://cwe.mitre.org/data/definitions/301.html'}],
            examples:[
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following example demonstrates the weakness.',
                    code: 'unsigned char *simple_digest(char *alg,char *buf,unsigned int len, int *olen) {\n' +
                        'const EVP_MD *m;\n' +
                        'EVP_MD_CTX ctx;\n' +
                        'unsigned char *ret;\n' +
                        'OpenSSL_add_all_digests();\n' +
                        'if (!(m = EVP_get_digestbyname(alg))) return NULL;\n' +
                        'if (!(ret = (unsigned char*)malloc(EVP_MAX_MD_SIZE))) return NULL;\n' +
                        'EVP_DigestInit(&ctx, m);\n' +
                        'EVP_DigestUpdate(&ctx,buf,len);\n' +
                        'EVP_DigestFinal(&ctx,ret,olen);\n' +
                        'return ret;\n' +
                        '}\n' +
                        'unsigned char *generate_password_and_cmd(char *password_and_cmd) {\n' +
                        'simple_digest("sha1",password,strlen(password_and_cmd)\n' +
                        '...\n' +
                        ');\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Authentication Bypass by Assumed-ImmutableData',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.7',
            title:'Authentication Bypass by Assumed-ImmutableData',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'The authentication scheme or implementation uses key data elements that are assumed to be immutable, but can be controlled or modified by the attacker.',
            mitigation:'To mitigate this threat, any immutable data fields should be properly protected such as environment variables, and form fields to ensure that those fields are not tempered with.',
            references:[{name:'CWE-302: Authentication Bypass by Assumed-Immutable Data', link:'https://cwe.mitre.org/data/definitions/302.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'In the following example, an "authenticated" cookie is used to determine whether or not a user should be granted access to a system.',
                    postText: 'Of course, modifying the value of a cookie on the client-side is trivial, but many developers assume that cookies are essentially immutable.',
                    code: 'boolean authenticated = new Boolean(getCookieValue("authenticated")).booleanValue();\n' +
                        'if (authenticated) {\n' +
                        '...\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Incorrect Implementation of AuthenticationAlgorithm',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.8',
            title:'Incorrect Implementation of AuthenticationAlgorithm',
            type:'Spoofing',
            status:'Open',
            severity:'Low',
            description:'The requirements for the software dictate the use of an established authentication algorithm, but the implementation of the algorithm is incorrect. [74]',
            mitigation:'To mitigate this threat, the algorithm should be fully tested, from endpoint to endpoint in a pre-production environment prior to being deployed ina production environment.',
            references:[{name:'CWE-303: Incorrect Implementation of Authentication Algorithm', link:'https://cwe.mitre.org/data/definitions/303.html'}]});});

    flow.rule('Missing Authentication for Critical Function',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Store" && isFalse(el.element.providesAuthenticationStore))|| (el.element.attributes.type == "tm.MobilePhone" && isFalse(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type == "tm.SmartWatch" && isFalse(el.element.providesAuthenticationSmartWatch))  || (el.element.attributes.type == "tm.Laptop" && isFalse(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isFalse(el.element.providesAuthenticationTablet))|| (el.element.attributes.type == "tm.Electrocardiogram" && isFalse(el.element.providesAuthenticationElectrocardiogram))  || (el.element.attributes.type == "tm.Pacemaker" && isFalse(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.9',
            title:'Missing Authentication for Critical Function',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'The software does not perform any authentication for functionality that requires a provable user identity or consumes a significant amount of resources [75].',
            mitigation:'To mitigate this threat there are several countermeasures that can be implemented. Firstly, the application should be split up based on privilege levels where it\’s maintained by a centralized authentication mechanism. Secondly, any security check that was implemented on the client side of an application should also be on the server side. Another migration technique is to avoid designing and implementing an authentication function that is custom-tailed to the application. Lastly, any library or framework which is known to have countermeasures that will have the authentication function.',
            references:[{name:'CWE-306: Missing Authentication for Critical Function', link:'https://cwe.mitre.org/data/definitions/306.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'In the following Java example the method createBankAccount is used to create a BankAccount object for a bank management application.',
                    postText: 'However, there is no authentication mechanism to ensure that the user creating this bank account object has the authority to create new bank accounts. Some authentication mechanisms should be used to verify that the user has the authority to create bank account objects.',
                    code: 'public BankAccount createBankAccount(String accountNumber, String accountType,\n' +
                        'String accountName, String accountSSN, double balance) {\n' +
                        'BankAccount account = new BankAccount();\n' +
                        'account.setAccountNumber(accountNumber);\n' +
                        'account.setAccountType(accountType);\n' +
                        'account.setAccountOwnerName(accountName);\n' +
                        'account.setAccountOwnerSSN(accountSSN);\n' +
                        'account.setBalance(balance);\n' +
                        '\n' +
                        'return account;\n' +
                        '}'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following Java code includes a boolean variable and method for authenticating a user. If the user has not been authenticated then the createBankAccount will not create the bank account object.',
                    code: 'private boolean isUserAuthentic = false;\n' +
                        '\n' +
                        '// authenticate user, \n' +
                        '\n' +
                        '// if user is authenticated then set variable to true \n' +
                        '\n' +
                        '// otherwise set variable to false \n' +
                        'public boolean authenticateUser(String username, String password) {\n' +
                        '...\n' +
                        '}\n' +
                        '\n' +
                        'public BankAccount createNewBankAccount(String accountNumber, String accountType,\n' +
                        'String accountName, String accountSSN, double balance) {\n' +
                        'BankAccount account = null;\n' +
                        '\n' +
                        'if (isUserAuthentic) {\n' +
                        'account = new BankAccount();\n' +
                        'account.setAccountNumber(accountNumber);\n' +
                        'account.setAccountType(accountType);\n' +
                        'account.setAccountOwnerName(accountName);\n' +
                        'account.setAccountOwnerSSN(accountSSN);\n' +
                        'account.setBalance(balance);\n' +
                        '}\n' +
                        'return account;\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Improper Restriction of Excessive Authentication Attempts',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.10',
            title:'Improper Restriction of Excessive Authentication Attempts',
            type:'Spoofing',
            status:'Open',
            severity:'Medium',
            description:'The software does not implement sufficient measures to prevent multiple failed authentication attempts within in a short time frame, making it more susceptible to brute force attacks [76].',
            mitigation:'To mitigate this threat, there are multiple techniques can be used such as disconnecting the user after a certain number of failed attempts,having a timeout after a certain number of attempts or locking out a targeted account [76].',
            references:[{name:'CWE-307: Improper Restriction of Excessive Authentication Attempts', link:'https://cwe.mitre.org/data/definitions/307.html'}],
            examples:[
                {
                    language: {name: 'PHP', highlightAlias: 'php'},
                    preText: 'This code attempts to limit the number of login attempts by causing the process to sleep before completing the authentication.',
                    postText: 'However, there is no limit on parallel connections, so this does not increase the amount of time an attacker needs to complete an attack.',
                    code: '$username = $_POST[\'username\'];\n' +
                        '$password = $_POST[\'password\'];\n' +
                        'sleep(2000);\n' +
                        '$isAuthenticated = authenticateUser($username, $password);'
                },
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'In the following C/C++ example the validateUser method opens a socket connection, reads a username and password from the socket and attempts to authenticate the username and password.',
                    postText: 'The validateUser method will continuously check for a valid username and password without any restriction on the number of authentication attempts made. The method should limit the number of authentication attempts made to prevent brute force attacks.',
                    code: 'int validateUser(char *host, int port)\n' +
                        '{\n' +
                        'int socket = openSocketConnection(host, port);\n' +
                        'if (socket < 0) {\n' +
                        'printf("Unable to open socket connection");\n' +
                        'return(FAIL);\n' +
                        '}\n' +
                        '\n' +
                        'int isValidUser = 0;\n' +
                        'char username[USERNAME_SIZE];\n' +
                        'char password[PASSWORD_SIZE];\n' +
                        '\n' +
                        'while (isValidUser == 0) {\n' +
                        'if (getNextMessage(socket, username, USERNAME_SIZE) > 0) {\n' +
                        'if (getNextMessage(socket, password, PASSWORD_SIZE) > 0) {\n' +
                        'isValidUser = AuthenticateUser(username, password);\n' +
                        '}\n' +
                        '}\n' +
                        '}\n' +
                        'return(SUCCESS);'
                }
            ]
        });});

    flow.rule('Use of Single-Factor Authentication',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.11',
            title:'Use of Single-Factor Authentication',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'The use of single-factor authentication can lead to unnecessary risk of compromise when compared with the benefits of a dual-factor authentication scheme.',
            mitigation:'To mitigate this threat, the system or application should use an extra method of authentication (multi-factor authentication). This ensures if one method is compromised, the system or application is still safe.',
            references:[{name:'CWE-308: Use of Single-factor Authentication', link:'https://cwe.mitre.org/data/definitions/308.html'}],
            examples:[
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'In this example a user is logged in if their given password matches a stored password:',
                    postText: 'This code fails to incorporate more than one method of authentication. If an attacker can steal or guess a user\'s password, they are given full access to their account. Note this code also exhibits Reversible One-Way Hash and Use of a One-Way Hash without a Salt.',
                    code: 'unsigned char *check_passwd(char *plaintext) {\n' +
                        'ctext = simple_digest("sha1",plaintext,strlen(plaintext), ... );\n' +
                        '//Login if hash matches stored hash \n' +
                        'if (equal(ctext, secret_password())) {\n' +
                        'login_user();\n' +
                        '}\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Key Exchange with Entity Authentication',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.12',
            title:'Key Exchange with Entity Authentication',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'The software performs a key exchange with an actor without verifying the identity of that actor.',
            mitigation:'There are two ways to mitigate this threat. Firstly,ensure when designing the system there is authentication involved. Lastly, validate that the checks that are actually verifying the identify of the user when communicating between identities.',
            references:[{name:'CWE-322: Key Exchange without Entity Authentication', link:'https://cwe.mitre.org/data/definitions/322.html'}]});});

    flow.rule('Weak Password Requirements',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.providesAuthenticationProcess))|| (el.element.attributes.type == "tm.Actor" && isTrue(el.element.providesAuthenticationActor)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.providesAuthenticationStore)) ||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.providesAuthenticationMobilePhone)) || (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.providesAuthenticationSmartWatch)) || (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.providesAuthenticationLaptop))|| (el.element.attributes.type == "tm.Tablet" && isTrue(el.element.providesAuthenticationTablet))|| (el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.providesAuthenticationElectrocardiogram)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.providesAuthenticationPacemaker))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.13',
            title:'Weak Password Requirements',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'The product does not require that users should have strong passwords, which makes it easier for attackers to compromise user accounts.',
            mitigation:'To mitigate this threat, a password policy must be in place to have strong passwords. A password policy (rules to make strong passwords) should in place to make a password much harder to guess for an attacker.Such an example of a password policy is as follows: All passwords should be reasonably complex and difficult for unauthorized people to guess. Employees and pupils should choose passwords that are at least eight characters long and contain a combination of upper-and lower-case letters, numbers, and punctuation marks and other special characters. These requirements will been forced with software when possible.',
            references:[{name:'Password Policy', link:'https://www.gloucestershire.gov.uk/media/8868/password_policy-67251.docx'},{name:'CWE-521: Weak Password Requirements', link:'https://cwe.mitre.org/data/definitions/521.html'}]});});

    flow.rule('Use of Client-Side Authentication',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.14',
            title:'Use of Client-Side Authentication',
            type:'Spoofing',
            status:'Open',
            severity:'Medium',
            description:'A client/server product performs authentication within client code but not in server code, allowing server-side authentication to be bypassed via a modified client that omits the authentication check.',
            mitigation:'To mitigate this threat, authentication must also be performed on the server side of the application or system.',
            references:[{name:'CWE-521: Weak Password Requirements', link:'https://cwe.mitre.org/data/definitions/603.html'}]});});

    flow.rule('Unverified Password Change',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.15',
            title:'Unverified Password Change',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'When setting a new password for a user, the product does not require knowledge of the original password, or using another form of authentication.',
            mitigation:'To mitigate this threat, two techniques can be implemented. Firstly, when there is a password change, the user must provide the original password. Lastly, a “Forget Password” option can be used, but ensure that the user is requesting a change through a challenge (ex: enter email to receive an email which contains a link to change their password) and not actually changing the user\’s properties until they\’ve clicked that link.',
            references:[{name:'CWE-620: Unverified Password Change', link:'https://cwe.mitre.org/data/definitions/620.html'}],
            examples:[
                {
                    language: {name: 'PHP', highlightAlias: 'php'},
                    preText: 'This code changes a user\'s password.',
                    postText: 'While the code confirms that the requesting user typed the same new password twice, it does not confirm that the user requesting the password change is the same user whose password will be changed. An attacker can request a change of another user\'s password and gain control of the victim\'s account.',
                    code: '$user = $_GET[\'user\'];\n' +
                        '$pass = $_GET[\'pass\'];\n' +
                        '$checkpass = $_GET[\'checkpass\'];\n' +
                        'if ($pass == $checkpass) {\n' +
                        'SetUserPassword($user, $pass);\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Weak Password Recovery Mechanism for Forgetten Password',[[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncryptedFlow)) ||(el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncryptedStore))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '9.16',
            title:'Weak Password Recovery Mechanism for Forgetten Password',
            type:'Spoofing',
            status:'Open',
            severity:'High',
            description:'The software contains a mechanism for users to recover or change their passwords without knowing the original password, but the mechanism is weak.',
            mitigation:'To mitigate this threat, there are several countermeasures that can be implemented. Ensure that all the input that goes through the mechanism is validated. If security questions are used, ensure that the questions are not simple and there are multiple questions. There should be a limit as to how many attempts one has to answer a question.The user must also answer the question before the password is reset. Do not allow the user to choose which email the password is sent to. As well, the original password should not be given, instead anew temporary password should be provided [83].',
            references:[{name:'CWE-640: Weak Password Recovery Mechanism for Forgotten Password', link:'https://cwe.mitre.org/data/definitions/640.html'}]});});

    flow.rule('External Control of System or Configuration Setting',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isFalse(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isFalse(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isFalse(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type == "tm.Pacemaker" && isFalse(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type == "tm.SmartWatch" && isFalse(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isFalse(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isFalse(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isFalse(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.1',
            title:'External Control of System or Configuration Setting',
            type:'Tampering',
            status:'Open',
            severity:'Medium',
            description:'One or more system settings or configuration elements can be externally controlled by a user[84].',
            mitigation:'To mitigate this threat, the system can be split up by privilege level, so the settings/control are only changed by authorized users. [84]',
            references:[{name:'CWE-15: External Control of System or Configuration Setting', link:'https://cwe.mitre.org/data/definitions/15.html'}],
            examples:[
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following C code accepts a number as one of its command line parameters and sets it as the host ID of the current machine.',
                    postText: 'Although a process must be privileged to successfully invoke sethostid(), unprivileged users may be able to invoke the program. The code in this example allows user input to directly control the value of a system setting. If an attacker provides a malicious value for host ID, the attacker can misidentify the affected machine on the network or cause other unintended behavior.',
                    code: '...\n' +
                        'sethostid(argv[1]);\n' +
                        '...'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'The following Java code snippet reads a string from an HttpServletRequest and sets it as the active catalog for a database Connection.',
                    postText: '...\n' +
                        'conn.setCatalog(request.getParameter("catalog"));\n' +
                        '...',
                    code: 'In this example, an attacker could cause an error by providing a nonexistent catalog name or connect to an unauthorized portion of the database.'
                }
            ]
        });});

    flow.rule('Process Control',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type == "tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type == "tm.SmartWatch") || (el.element.attributes.type == "tm.Laptop") || (el.element.attributes.type == "tm.Tablet") || (el.element.attributes.type == "tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.2',
            title:'Process Control',
            type:'Tampering',
            status:'Open',
            severity:'High',
            description:'Executing commands or loading libraries from an untrusted source or in an untrusted environment can cause an application to execute malicious commands (and payloads) on behalf of an attacker[85].',
            mitigation:'To mitigate this threat, libraries and frameworks that are used must be from a trusted source, where these libraries can be relied upon and not be maliciously used by an adversary. [85]',
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

    flow.rule('Sensitive Data Under Web Root',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.isAWebApplication))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.3',
            title:'Sensitive Data Under Web Root',
            type:'Information disclosure',
            status:'Open',
            severity:'Medium',
            description:'The application stores sensitive data under the web document root with insufficient access control, which might make it accessible to untrusted parties.',
            mitigation:'To mitigate this threat, avoid storing information under the web root directory, and access controls should be implemented to not allow these files tobe read or written to [86]',
            references:[{name:'CWE-219: Sensitive Data Under Web Root', link:'https://cwe.mitre.org/data/definitions/219.html'}]});});

    flow.rule('Incorrect Privilege Assignment',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.4',
            title:'Incorrect Privilege Assignment',
            type:'Elevation of privilege',
            status:'Open',
            severity:'High',
            description:'A product incorrectly assigns a privilege to a particular actor, creating an unintended sphere of control for that actor [87].',
            mitigation:'To mitigate this threat, the settings, management sand handling of privileges must be managed carefully. There should be accounts with limited privileges if there is a task that needs to be done,with very specific privilege levels. [87]',
            references:[{name:'CWE-266: Incorrect Privilege Assignment', link:'https://cwe.mitre.org/data/definitions/266.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'Evidence of privilege change:',
                    code: 'AccessController.doPrivileged(new PrivilegedAction() {\n' +
                        'public Object run() {\n' +
                        '\n' +
                        '// privileged code goes here, for example: \n' +
                        'System.loadLibrary("awt");\n' +
                        'return null;\n' +
                        '// nothing to return \n' +
                        '}'
                },
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'This application sends a special intent with a flag that allows the receiving application to read a data file for backup purposes.',
                    postText: 'Any malicious application can register to receive this intent. Because of the FLAG_GRANT_READ_URI_PERMISSION included with the intent, the malicious receiver code can read the user\'s data.',
                    code: 'Intent intent = new Intent();\n' +
                        'intent.setAction("com.example.BackupUserData");\n' +
                        'intent.setData(file_uri);\n' +
                        'intent.addFlags(FLAG_GRANT_READ_URI_PERMISSION);\n' +
                        'sendBroadcast(intent);'
                }
            ]
        });});

    flow.rule('Privilege Defined With Unsafe Actions',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type == "tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type == "tm.SmartWatch") || (el.element.attributes.type == "tm.Laptop") || (el.element.attributes.type == "tm.Tablet") || (el.element.attributes.type == "tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.5',
            title:'Privilege Defined With Unsafe Actions',
            type:'Elevation of privilege',
            status:'Open',
            severity:'High',
            description:'A particular privilege, role, capability, or right can be used to perform unsafe actions that were not intended, even when it is assigned to the correct entity.',
            mitigation:'To mitigate this threat, the settings, managements and handling of privileges must be managed carefully. There should be accounts with limited privileges if there is a task that needs to be done,with very specific privilege levels [88].',
            references:[{name:'CWE-267: Privilege Defined With Unsafe Actions', link:'https://cwe.mitre.org/data/definitions/267.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'This code intends to allow only Administrators to print debug information about a system.',
                    postText: 'While the intention was to only allow Administrators to print the debug information, the code as written only excludes those the with the role of "GUEST". Someone with the role of "ADMIN" or "USER" will be allowed access, which goes against the original intent. An attacker may be able to use this debug information to craft an attack on the system.',
                    code: 'public enum Roles {\n' +
                        'ADMIN,USER,GUEST\n' +
                        '}\n' +
                        '\n' +
                        'public void printDebugInfo(User requestingUser){\n' +
                        'if(isAuthenticated(requestingUser)){\n' +
                        'switch(requestingUser.role){\n' +
                        'case GUEST:\n' +
                        'System.out.println("You are not authorized to perform this command");\n' +
                        'break;\n' +
                        '\n' +
                        'default:\n' +
                        'System.out.println(currentDebugState());\n' +
                        'break;\n' +
                        '}\n' +
                        '}\n' +
                        'else{\n' +
                        'System.out.println("You must be logged in to perform this command");\n' +
                        '}\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Privilege Chaining',[[Element, 'el','(el.element.attributes.type == "tm.Process") ||(el.element.attributes.type == "tm.Store") ||(el.element.attributes.type == "tm.MobilePhone") ||(el.element.attributes.type == "tm.Pacemaker")|| (el.element.attributes.type == "tm.SmartWatch") || (el.element.attributes.type == "tm.Laptop") || (el.element.attributes.type == "tm.Tablet") || (el.element.attributes.type == "tm.Electrocardiogram")'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.6',
            title:'Privilege Chaining',
            type:'Elevation of privilege',
            status:'Open',
            severity:'High',
            description:'Two distinct privileges, roles, capabilities, or rights can be combined in a way that allows an entity to perform unsafe actions that would not be allowed without that combination [89].',
            mitigation:'To mitigate this threat, the settings, managements and handling of privileges must be managed carefully. There should be accounts with limited privileges if there is a task that needs to be done,with very specific privilege levels. In addition to those techniques, privileges should be separated where multiple conditions need to be met to access[89].',
            references:[{name:'CWE-268: Privilege Chaining', link:'https://cwe.mitre.org/data/definitions/268.html'}],
            examples:[
                {
                    language: {name: 'Java', highlightAlias: 'java'},
                    preText: 'This code allows someone with the role of "ADMIN" or "OPERATOR" to reset a user\'s password. The role of "OPERATOR" is intended to have less privileges than an "ADMIN", but still be able to help users with small issues such as forgotten passwords.',
                    postText: 'This code does not check the role of the user whose password is being reset. It is possible for an Operator to gain Admin privileges by resetting the password of an Admin account and taking control of that account.',
                    code: 'public enum Roles {\n' +
                        'ADMIN,OPERATOR,USER,GUEST\n' +
                        '}\n' +
                        '\n' +
                        'public void resetPassword(User requestingUser, User user, String password ){\n' +
                        'if(isAuthenticated(requestingUser)){\n' +
                        'switch(requestingUser.role){\n' +
                        'case GUEST:\n' +
                        'System.out.println("You are not authorized to perform this command");\n' +
                        'break;\n' +
                        '\n' +
                        'case USER:\n' +
                        'System.out.println("You are not authorized to perform this command");\n' +
                        'break;\n' +
                        '\n' +
                        'default:\n' +
                        'setPassword(user,password);\n' +
                        'break;\n' +
                        '}\n' +
                        '}\n' +
                        '\n' +
                        'else{\n' +
                        'System.out.println("You must be logged in to perform this command");\n' +
                        '}\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Improper Privilege Management',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isFalse(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isFalse(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isFalse(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type == "tm.Pacemaker" && isFalse(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type == "tm.SmartWatch" && isFalse(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isFalse(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isFalse(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isFalse(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.7',
            title:'Improper Privilege Management',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The software does not properly assign, modify,track, or check privileges for an actor, creating an unintended sphere of control for that actor [90].',
            mitigation:'To mitigate this threat three techniques are possible counter measures to properly manage privileges. There should be specific trust zones in the system, the least privilege principle should be in effect where the access rights of each user are given the minimum privilege level to do their task as well, privileges should be separated where multiple conditions need to be met to access [90].',
            references:[{name:'CWE-269: Improper Privilege Management', link:'https://cwe.mitre.org/data/definitions/269.html'}]});});

    flow.rule('Privilege Context Switching Error',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.8',
            title:'Privilege Context Switching Error',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The software does not properly manage privileges while it is switching between different contexts that have different privileges or spheres of control [91].',
            mitigation:'To mitigate this threat, three techniques are possible counter measures to properly manage privileges in different contexts. There should be specific trust zones in the system, the least privilege principle should be in effect where the access rights of each user are given the minimum privilege level to do their task as well, privileges should be separated where multiple conditions need to be met to access [91].',
            references:[{name:'CWE-270: Privilege Context Switching Error', link:'https://cwe.mitre.org/data/definitions/270.html'}]});});

    flow.rule('Privilege Dropping or Lowering Errors',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.9',
            title:'Privilege Dropping or Lowering Errors',
            type:'Elevation of privilege',
            status:'Open',
            severity:'High',
            description:'The software does not drop privileges before passing control of a resource to an actor that does not have those privileges [92].',
            mitigation:'To mitigate this threat, three techniques a possible counter measures to properly manage privileges in different contexts. There should be specific trust zones in the system, the least privilege principle should be in effect where the access rights of each user are given the minimum privilege level to do their task as well, privileges should be separated where multiple conditions need to be met to access [92].',
            references:[{name:'CWE-271: Privilege Dropping / Lowering Errors', link:'https://cwe.mitre.org/data/definitions/271.html'}],
            examples:[
                {
                    language: {name: 'C', highlightAlias: 'c'},
                    preText: 'The following code calls chroot() to restrict the application to a subset of the filesystem below APP_HOME in order to prevent an attacker from using the program to gain unauthorized access to files located elsewhere. The code then opens a file specified by the user and processes the contents of the file.',
                    postText: 'Constraining the process inside the application\'s home directory before opening any files is a valuable security measure. However, the absence of a call to setuid() with some non-zero value means the application is continuing to operate with unnecessary root privileges. Any successful exploit carried out by an attacker against the application can now result in a privilege escalation attack because any malicious operations will be performed with the privileges of the superuser. If the application drops to the privilege level of a non-root user, the potential for damage is substantially reduced.',
                    code: 'chroot(APP_HOME);\n' +
                        'chdir("/");\n' +
                        'FILE* data = fopen(argv[1], "r+");\n' +
                        '...'
                }
            ]
        });});

    flow.rule('Improper Check for Dropped Privileges',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.10',
            title:'Improper Check for Dropped Privileges',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The software attempts to drop privileges but does not check or incorrectly checks to see if the drop succeeded [93].',
            mitigation:'To mitigate this threat, there are two techniques that can counter against an improper check for dropped privileges. Firstly, the system should be designed from the point of view of privilege level,where there are entry points and trust boundaries to interface components of different privilege levels. Ensure that all functions return a value, and verify that the result is expected [93].',
            references:[{name:'CWE-273: Improper Check for Dropped Privileges', link:'https://cwe.mitre.org/data/definitions/273.html'}],
            examples:[
                {
                    language: {name: 'C++', highlightAlias: 'cpp'},
                    preText: 'This code attempts to take on the privileges of a user before creating a file, thus avoiding performing the action with unnecessarily high privileges:',
                    postText: 'The call to ImpersonateNamedPipeClient may fail, but the return value is not checked. If the call fails, the code may execute with higher privileges than intended. In this case, an attacker could exploit this behavior to write a file to a location that the attacker does not have access to.',
                    code: 'bool DoSecureStuff(HANDLE hPipe) {\n' +
                        'bool fDataWritten = false;\n' +
                        'ImpersonateNamedPipeClient(hPipe);\n' +
                        'HANDLE hFile = CreateFile(...);\n' +
                        '/../\n' +
                        'RevertToSelf()\n' +
                        '/../\n' +
                        '}'
                }
            ]
        });});

    flow.rule('Incorrect Default Permissions',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.11',
            title:'Incorrect Default Permissions',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The software, upon installation, sets incorrect permissions for an object that exposes it to an unintended actor [94].',
            mitigation:'To mitigate the threat of default permissions the settings, management and handling of privileges should be carefully managed [94].',
            references:[{name:'CWE-276: Incorrect Default Permissions', link:'https://cwe.mitre.org/data/definitions/276.html'}]});});

    flow.rule('Insecure Inherited Permissions',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.12',
            title:'Insecure Inherited Permissions',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Low',
            description:'A product defines a set of insecure permissions that are inherited by objects that are created by the program [95].',
            mitigation:'To mitigate this threat, the settings, management and handling of privileges need to be managed properly [95].',
            references:[{name:'CWE-277: Insecure Inherited Permissions', link:'https://cwe.mitre.org/data/definitions/277.html'}]});});

    flow.rule('Incorrect Execution-Assigned Permissions',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.13',
            title:'Incorrect Execution-Assigned Permissions',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'While it is executing, the software sets the permissions of an object in a way that violates the intended permissions that have been specified by the user [96].',
            mitigation:'To mitigate this threat, the settings, management and handling of privileges need to be managed properly [96].',
            references:[{name:'CWE-279: Incorrect Execution-Assigned Permissions', link:'https://cwe.mitre.org/data/definitions/279.html'}]});});

    flow.rule('Improper Handling of Insufficient Permissions or Privileges',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.14',
            title:'Improper Handling of Insufficient Permissions or Privileges',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The application does not handle or incorrectly handles when it has insufficient privileges to access resources or functionality as specified by their permissions. This may cause it to follow unexpected code paths that may leave the application in an invalid state [97].',
            mitigation:'To mitigate this threat, there should be areas where there are specific permission levels. In addition,verify that if an access to a resource or system functionality is successful or not in all privilege levels. [97]',
            references:[{name:'CWE-280: Improper Handling of Insufficient Permissions or Privileges', link:'https://cwe.mitre.org/data/definitions/280.html'}]});});

    flow.rule('Improper Ownership Management',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isTrue(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isTrue(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isTrue(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isTrue(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type == "tm.Pacemaker" && isTrue(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type == "tm.SmartWatch" && isTrue(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isTrue(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isTrue(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isTrue(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.15',
            title:'Improper Ownership Management',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Medium',
            description:'The software assigns the wrong ownership, or does not properly verify the ownership, of an object or resource [98].',
            mitigation:'To mitigate this threat, the settings, management and handling of privilege needs to managed carefully [98].',
            references:[{name:'CWE-282: Improper Ownership Management ', link:'https://cwe.mitre.org/data/definitions/282.html'}]});});

    flow.rule('Unverified Ownership',[[Element, 'el','(el.element.attributes.type == "tm.Process" && isFalse(el.element.privilegeLevelForProcess)) ||(el.element.attributes.type ==  "tm.Actor" && isFalse(el.element.privilegeLevelForActor))||(el.element.attributes.type == "tm.Store" && isFalse(el.element.privilegeLevelForStore))||(el.element.attributes.type == "tm.MobilePhone" && isFalse(el.element.privilegeLevelForMobilePhone)) || (el.element.attributes.type == "tm.Pacemaker" && isFalse(el.element.privilegeLevelForPacemaker))|| (el.element.attributes.type == "tm.SmartWatch" && isFalse(el.element.privilegeLevelForSmartWatch))|| (el.element.attributes.type == "tm.Laptop" && isFalse(el.element.privilegeLevelForLaptop)) ||(el.element.attributes.type == "tm.Tablet" && isFalse(el.element.privilegeLevelForTablet)) ||(el.element.attributes.type == "tm.Electrocardiogram" && isFalse(el.element.privilegeLevelForElectrocardiogram))'],
        [Threats, 'threats']
    ], function (facts) {
        facts.threats.collection.push({ ruleId: '10.16',
            title:'Unverified Ownership',
            type:'Elevation of privilege',
            status:'Open',
            severity:'Low',
            description:'The software does not properly verify that a critical resource is owned by the proper entity [99].',
            mitigation:'To mitigate the threat of unverified ownership, the settings, management and handling of privilege needs to be managed carefully and the application needs to be designed from a separation of privilege point of view, which will require multiple conditions to access a resource. [99]',
            references:[{name:'CWE-283: Unverified Ownership', link:'https://cwe.mitre.org/data/definitions/283.html'}],
            examples:[
                {
                    language: {name: 'Python', highlightAlias: 'python'},
                    preText: 'This function is part of a privileged program that takes input from users with potentially lower privileges.',
                    postText: 'This code does not confirm that the process to be killed is owned by the requesting user, thus allowing an attacker to kill arbitrary processes.',
                    code: 'def killProcess(processID):\n' +
                        'os.kill(processID, signal.SIGKILL)'
                },
                {
                    language: {name: 'Python', highlightAlias: 'python'},
                    preText: 'This function remedies the problem by checking the owner of the process before killing it:',
                    code: 'def killProcess(processID):\n' +
                        'user = getCurrentUser()\n' +
                        '\n' +
                        '#Check process owner against requesting user \n' +
                        'if getProcessOwner(processID) == user:\n' +
                        'os.kill(processID, signal.SIGKILL)\n' +
                        'return\n' +
                        '\n' +
                        'else:\n' +
                        'print("You cannot kill a process you don\'t own")\n' +
                        'return'
                }
            ]
        });});
});

}
}

module.exports = threatengine;
