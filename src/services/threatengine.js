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
            flow.rule('Empty String Password', [[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials) && isTrue(el.element.remoteMedicalRecordStorage)'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '1.1',
                    title:'Empty String Password',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'Using an empty string as a password is insecure.It is never appropriate to use an empty string as a password. It is too easy to guess. An empty string password makes the authentication as weak as the user names, which are normally public or guessable. This makes a brute-force attack against the login interface much easier.',
                    mitigation:'To counter this threat, a password policy (rules to make strong passwords) should in place to make a password much harder to guess for an attacker. Such an example of a password policy is as follows:All passwords should be reasonably complex and difficult for unauthorized people to guess.  Employees and pupils should choose passwords that are at least eight characters long and contain a combination of upper- and lower-case letters, numbers, and punctuation marks and other special characters.  These requirements will be enforced with software when possible.  [1]'});});

            flow.rule('Password in Configuration File', [[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials)'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '1.2',
                    title:'Password in Configuration File',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'Medium',
                    description:'Storing a password in a configuration file allows anyone who can read the file access to the password-protected resource. Developers sometimes believe that they cannot defend the application from someone who has access to the configuration, but this attitude makes an attacker\'s job easier.',
                    mitigation:'To mitigate this threat, 2 mitigations are required. The configuration file needs to employ a form of Access Control to ensure only those who have the privilege to access that file, are the only ones allowed to access that [2]. To control the information contained in the configuration file, the passwords should be stored in encrypted text which will combine the use of hash functions and the use of salts to take any password of any size and produce a unique hash value of the password and combine it with the original password, that way the password cannot be determined from the file [2]. '});});

            flow.rule('Hardcoded Password', [[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials)'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '1.3',
                    title:'Hardcoded Password',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'Hardcoded passwords may compromise system security in a way that cannot be easily remedied.It is never a good idea to hardcode a password. Not only does hardcoding a password allow all the project\'s developers to view the password, it also makes fixing the problem extremely difficult. Once the code is in production, the password cannot be changed without patching the software. If the account protected by the password is compromised, the owners of the system will be forced to choose between security and availability.',
                    mitigation:'To counter this threat of hardcoding passwords, there are several mitigations/countermeasures that can be implemented:Ask user for the password.  The program should not know the password of a user.  The user should be presented with a challenge to enter their password for the program to not be compromised easily [5]. If an existing password is stored on an Authentication distributed server such as an AFS (Andrew Filesystem [6]) or Kerberos, obtain the passwords from the server [5]. Have the password stored in a separate configuration file, where that file is strictly read access only and has a level of access control that only certain individuals and processes who have the right privilege can read the file [5]. '});});

            flow.rule('Password Plaintext Storage', [[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials)'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '1.4',
                    title:'Password Plaintext Storage',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'Storing a password in plaintext may result in a system compromise.Password management issues occur when a password is stored in plaintext in an application\'s properties or configuration file. A programmer can attempt to remedy the password management problem by obscuring the password with an encoding function, such as base 64 encoding, but this effort does not adequately protect the password.',
                    mitigation:'Passwords should never be stored in plain text.  Rather these passwords should be stored in encrypted text which will combine the use of hash functions and the use of salts to take any password of any size and produce a unique hash value of the password and combine it with the original password, that way the password cannot be determined from the file.  [2]'});});

            flow.rule('Least Privilege Violation', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '1.5',
                    title:'Least Privilege Violation',
                    type:'Elevation of privilege',
                    status:'Open',
                    severity:'Medium',
                    description:'The elevated privilege level required to perform operations such as chroot() should be dropped immediately after the operation is performed.When a program calls a privileged function, such as chroot(), it must first acquire root privilege. As soon as the privileged operation has completed, the program should drop root privilege and return to the privilege level of the invoking user.',
                    mitigation:'There are several ways to mitigate the least privilege violation:Split an individual components into several components, and assign lower privilege levels to those components [8]. Identify areas in the system which have that elevated privilege and use those  components instead to accomplish the task [8]. Create a separate environment within the system/program where only within that area or environment has an elevated privilege [8]. '});});

            flow.rule('Code Permission', [[Element, 'el','el.element.attributes.type == "tm.Actor"'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '1.6',
                    title:'Code Permission',
                    type:'Elevation of privilege',
                    status:'Open',
                    severity:'High',
                    description:'An active developer with access to unrelated module code may tamper or disclose sensitive project information (Interproject Code Access).',
                    mitigation:'Throughout the development lifecycle, there are several mitigations that can be used:Within the Implementation phase, if a critical resource is being used, there should be a check to see if a resource has permissions/behavior which are not secure (such as a regular user being able to modify that resource).  If there are such behaviors or permissions that exist, the program should create an error or exit the program [10]. Within the Architecture and Design phase, one should split up the software components based on privilege level and if possible, control what data, functions and resources each component uses based the privilege level [10].  Another option in this phase is to create a separate environment within the system/program where only within that area or environment has an elevated privilege [8]. In the installation phase, default or most restrictive permissions should be set to avoid any code which doesn\\t have the permissions to be run.  Also, the assumption that a system administrator will change the settings based on a manual is incorrect [10]. In the System Configuration phase, The configurable, executable files and libraries should be only have read and write access by the system administrator [10]. In the Documentation phase, within any documentation, any configurations that are suggested must be secure, and do not affect the operation of the computer or program [10]. Code Quality'});});

            flow.rule('Double Free Error', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '2.1',
                    title:'Double Free Error',
                    type:'Tampering',
                    status:'Open',
                    severity:'High',
                    description:'Double free errors occur when free() is called more than once with the same memory address as an argument.Calling free() twice on the same value can lead to memory leak. When a program calls free() twice with the same argument, the program\'s memory management data structures become corrupted and could allow a malicious user to write values in arbitrary memory spaces. This corruption can cause the program to crash or, in some circumstances, alter the execution flow. By overwriting registers or memory spaces, an attacker can trick the program into executing code of his/her own choosing, often resulting in an interactive shell with elevated permissions.When a buffer is free(), a linked list of free buffers is read to rearrange and combine the chunks of free memory (to be able to allocate larger buffers in the future). These chunks are laid out in a double linked list which points to previous and next chunks. Unlinking an unused buffer (which is what happens when free() is called) could allow an attacker to write arbitrary values in memory; essentially overwriting valuable registers, calling shellcode from its own buffer.',
                    mitigation:'To mitigate this threat, each allocation should only be freed once.  Once the memory has been allocated, the pointer should be set to NULL to ensure the pointer cannot be freed again.  In complicated error conditions, ensure that clean-up routines represent the state of allocation.  If the language is object oriented, that object destructors delete each allocation of memory one time only [11]. '});});

            flow.rule('Leftover Debug Code', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '2.2',
                    title:'Leftover Debug Code',
                    type:'Tampering',
                    status:'Open',
                    severity:'Medium',
                    description:'Debug code can create unintended entry points in a deployed web application.A common development practice is to add \"back door\" code specifically designed for debugging or testing purposes that is not intended to be shipped or deployed with the application. When this sort of debug code is accidentally left in the application, the application is open to unintended modes of interaction. These back-door entry points create security risks because they are not considered during design or testing and fall outside of the expected operating conditions of the application.',
                    mitigation:'To mitigate this threat, all debug code should be removed prior to delivery of code [12]. '});});

            flow.rule('Memory Leak', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '2.3',
                    title:'Memory Leak',
                    type:'Denial of service',
                    status:'Open',
                    severity:'High',
                    description:'A memory leak is an unintentional form of memory consumption whereby the developer fails to free an allocated block of memory when no longer needed. The consequences of such an issue depend on the application itself. Consider the following general three cases:Short Lived User-land Application: Little if any noticeable effect. Modern operating system recollects lost memory after program termination.Long Lived User-land Application: Potentially dangerous. These applications continue to waste memory over time, eventually consuming all RAM resources. Leads to abnormal system behavior.Kernel-land Process: Memory leaks in the kernel level lead to serious system stability issues. Kernel memory is very limited compared to user land memory and should be handled cautiously.Memory is allocated but never freed. Memory leaks have two common and sometimes overlapping causes:Error conditions and other exceptional circumstances.Confusion over which part of the program is responsible for freeing the memory.Most memory leaks result in general software reliability problems, but if an attacker can intentionally trigger a memory leak, the attacker might be able to launch a denial of service attack (by crashing the program) or take advantage of other unexpected program behavior resulting from a low memory condition.',
                    mitigation:'To mitigate that threat, 3rd party tools/software are required to see if this vulnerability exists in the code.  One such tool that can be used in a Unix/Linux environment is a program called Valgrind.  This program will run the desired software program to be checked to check all memory allocation and de-allocation methods are working as intended.  [13]'});});

            flow.rule('Null Dereference', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '2.4',
                    title:'Null Dereference',
                    type:'Denial of service',
                    status:'Open',
                    severity:'Medium',
                    description:'The program can potentially dereference a null pointer, thereby raising a NullPointerException. Null pointer errors are usually the result of one or more programmer assumptions being violated. Most null pointer issues result in general software reliability problems, but if an attacker can intentionally trigger a null pointer dereference, the attacker might be able to use the resulting exception to bypass security logic or to cause the application to reveal debugging information that will be valuable in planning subsequent attacks.A null-pointer dereference takes place when a pointer with a value of NULL is used as though it pointed to a valid memory area.Null-pointer dereferences, while common, can generally be found and corrected in a simple way. They will always result in the crash of the process, unless exception handling (on some platforms) is invoked, and even then, little can be done to salvage the process.',
                    mitigation:'To mitigate this threat, if possible, this vulnerability would be prevented, if the programming language that was used to program the software did not use pointers.  Another mitigation suggestion is to check to see if the pointers are referenced correctly prior to their use [14]. '});});

            flow.rule('Logging Practices', [[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.isALog)'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '2.5',
                    title:'Logging Practices',
                    type:'Repudiation',
                    status:'Open',
                    severity:'Low',
                    description:'Declare Logger Object as Static and Final:It is good programming practice to share a single logger object between all of the instances of a particular class and to use the same logger for the duration of the program.Don\'t Use Multiple Loggers:It is a poor logging practice to use multiple loggers rather than logging levels in a single class.Good logging practice dictates the use of a single logger that supports different logging levels for each class.Don\'t Use System Output Stream:Using System.out or System.err rather than a dedicated logging facility makes it difficult to monitor the behavior of the program. It can also cause log messages accidentally returned to the end users, revealing internal information to attackers. While most programmers go on to learn many nuances and subtleties about Java, a surprising number hang on to this first lesson and never give up on writing messages to standard output using System.out.println().The problem is that writing directly to standard output or standard error is often used as an unstructured form of logging. Structured logging facilities provide features like logging levels, uniform formatting, a logger identifier, timestamps, and, perhaps most critically, the ability to direct the log messages to the right place. When the use of system output streams is jumbled together with the code that uses loggers properly, the result is often a well-kept log that is missing critical information. In addition, using system output streams can also cause log messages accidentally returned to end users, revealing application internal information to attackers.Developers widely accept the need for structured logging, but many continue to use system output streams in their \"pre-production\" development. If the code you are reviewing is past the initial phases of development, use of System.out or System.err may indicate an oversight in the move to a structured logging system.',
                    mitigation:'To mitigate this threat the logging system should be centralized to the program and give different levels of detail, and log/display all security successes or failures.  [17]'});});

            flow.rule('Portability', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '2.6',
                    title:'Portability',
                    type:'Tampering',
                    status:'Open',
                    severity:'Low',
                    description:'Functions with inconsistent implementations across operating systems and operating system versions cause portability problems.The behavior of functions in this category varies by operating system, and at times, even by operating system version. Implementation differences can include:Slight differences in the way parameters are interpreted, leading to inconsistent results.Some implementations of the function carry significant security risks.The function might not be defined on all platforms.',
                    mitigation:'None for now.  COME BACK'});});

            flow.rule('Undefined Behavior', [[Element, 'el','el.element.attributes.type == "tm.Process"|| el.element.attributes.type == "tm.Store"'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '2.7',
                    title:'Undefined Behavior',
                    type:'Tampering',
                    status:'Open',
                    severity:'Low',
                    description:'The behavior of this function is undefined unless its control parameter is set to a specific value.The Linux Standard Base Specification 2.0.1 for libc places constraints on the arguments to some internal functions.',
                    mitigation:'None for now.  COME BACK'});});

            flow.rule('Unreleased Resource', [[Element, 'el','el.element.attributes.type == "tm.Process"|| el.element.attributes.type == "tm.Store"'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '2.8',
                    title:'Unreleased Resource',
                    type:'Denial of service',
                    status:'Open',
                    severity:'Medium',
                    description:'Most unreleased resource issues result in general software reliability problems, but if an attacker can intentionally trigger a resource leak, the attacker might be able to launch a denial of service attack by depleting the resource pool.Resource leaks have at least two common causes:Error conditions and other exceptional circumstances.Confusion over which part of the program is responsible for releasing the resource.',
                    mitigation:'To mitigate this threat, the programming language used to program the desired program, should not allow this threat to occur.  Another suggestion is to free all resources that have been allocated and be consistent in terms of how memory is allocated and de-allocated.  To furthermore mitigate this threat, is to release all the member components of a given object [27]. '});});

            flow.rule('Use of Obsolete Methods', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '2.9',
                    title:'Use of Obsolete Methods',
                    type:'Denial of service',
                    status:'Open',
                    severity:'Medium',
                    description:'The use of deprecated or obsolete functions may indicate neglected code.As programming languages evolve, functions occasionally become obsolete due to:Advances in the languageImproved understanding of how operations should be performed effectively and securelyChanges in the conventions that govern certain operationsFunctions that are removed are usually replaced by newer counterparts that perform the same task in some different and hopefully improved way.Refer to the documentation for this function in order to determine why it is deprecated or obsolete and to learn about alternative ways to achieve the same functionality. The remainder of this text discusses general problems that stem from the use of deprecated or obsolete functions.',
                    mitigation:'To mitigate this threat, the documentation for the program should be referred to, to determine the reason it is deprecated and to determine alternatives to using those methods, which may pose not only a function concern, but also a security concern.  [26]Cryptography'});});

            flow.rule('Sensitive Parameters in URL', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '3.1',
                    title:'Sensitive Parameters in URL',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'Medium',
                    description:'Information exposure through query strings in URL is when sensitive data is passed to parameters in the URL. This allows attackers to obtain sensitive data such as usernames, passwords, tokens (authX), database details, and any other potentially sensitive data. Simply using HTTPS does not resolve this vulnerability. A very common example is in GET requests.',
                    mitigation:'To mitigate this threat, it is recommended to use a POST method, as those parameters that are passed in through the URL are not saved, and therefore cannot be exposed.  [28]'});});

            flow.rule('Insecure Randomness', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '3.2',
                    title:'Insecure Randomness',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'Medium',
                    description:'Standard pseudo-random number generators cannot withstand cryptographic attacks.Insecure randomness errors occur when a function that can produce predictable values is used as a source of randomness in security-sensitive context.Computers are deterministic machines, and as such are unable to produce true randomness. Pseudo-Random Number Generators (PRNGs) approximate randomness algorithmically, starting with a seed from which subsequent values are calculated.There are two types of PRNGs: statistical and cryptographic. Statistical PRNGs provide useful statistical properties, but their output is highly predictable and forms an easy to reproduce numeric stream that is unsuitable for use in cases where security depends on generated values being unpredictable. Cryptographic PRNGs address this problem by generating output that is more difficult to predict. For a value to be cryptographically secure, it must be impossible or highly improbable for an attacker to distinguish between it and a truly random value. In general, if a PRNG algorithm is not advertised as being cryptographically secure, then it is probably a statistical PRNG and should not be used in security-sensitive contexts.',
                    mitigation:'To mitigate this threat, there are several countermeasures that can be implemented:Use an algorithm that is suggested to be strong by experts, in terms of randomness and that produces an adequate seed length.  A 256 bit seed length is a good starting point to produce a random number that is challenging to predict. Use static analysis tools to predict if such a random number or value will be produced again. Use manual testing techniques such as penetration testing and threat modelling to allow the tester to see if a random number or value is produced.  Automation tools are ineffective at determining the predictability due to the randomness of the algorithm and various business rules [29]. '});});

            flow.rule('Insufficient Entropy', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '3.3',
                    title:'Insufficient Entropy',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'Medium',
                    description:'When an undesirably low amount of entropy is available. Pseudo Random Number Generators are susceptible to suffering from insufficient entropy when they are initialized, because entropy data may not be available to them yet.In many cases a PRNG uses a combination of the system clock and entropy to create seed data. If insufficient entropy is available, an attacker can reduce the size magnitude of the seed value considerably. Furthermore, by guessing values of the system clock, they can create a manageable set of possible PRNG outputs.',
                    mitigation:'To mitigate this threat, a PRNG generally stores their previous value prior to gracefully exiting or shutting down.  If that value is used when the PRNG starts back up, the risk of entropy is reduced.  [30]'});});

            flow.rule('Improper Certificate Validation', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '3.4',
                    title:'Improper Certificate Validation',
                    type:'Tampering',
                    status:'Open',
                    severity:'High',
                    description:'The software does not validate, or incorrectly validates, a certificate.[35]',
                    mitigation:'Certificates should be carefully managed and check to assure that data are encrypted with the intended owner\\s public key. If certificate pinning is being used, ensure that all relevant properties of the certificate are fully validated before the certificate is pinned, including the hostname. [35]'});});

            flow.rule('Insufficient TLS Protection', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isFalse(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '3.5',
                    title:'Insufficient TLS Protection',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'Sensitive data must be protected when it is transmitted through the network. Such data can include user credentials and credit cards. As a rule of thumb, if data must be protected when it is stored, it must be protected also during transmission.HTTP is a clear-text protocol and it is normally secured via an SSL/TLS tunnel, resulting in HTTPS traffic. The use of this protocol ensures not only confidentiality, but also authentication. Servers are authenticated using digital certificates and it is also possible to use client certificate for mutual authentication.Even if high grade ciphers are today supported and normally used, some misconfiguration in the server can be used to force the use of a weak cipher - or at worst no encryption - permitting to an attacker to gain access to the supposed secure communication channel. Other misconfiguration can be used for a Denial of Service attack.See: https://www.owasp.org/index.php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)for more information',
                    mitigation:'To mitigate this threat, web servers that provide https services should have their configuration checked.  As well, the validity of an SSL certificate should be checked from a client and server point of view.  These would be checked using a variety of tools which are found on the following website:https://www. owasp. org/index. php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)  [31]'});});

            flow.rule('Hard-coded Cryptographic Key', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '3.6',
                    title:'Hard-coded Cryptographic Key',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'The use of a hard-coded cryptographic key tremendously increases the possibility that encrypted data may be recovered.Authentication: If hard-coded cryptographic keys are used, it is almost certain that malicious users will gain access through the account in question.',
                    mitigation:'To mitigate against this threat, this practice of hard coding the cryptographic key should be avoided to avoid exposing the cryptographic key to a potential adversary for exploitation [32]'});});

            flow.rule('Faulty Cryptographic Algorithm', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '3.7',
                    title:'Faulty Cryptographic Algorithm',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'Attempting to create non-standard and non-tested algorithms, using weak algorithms, or applying algorithms incorrectly will pose a high weakness to data that is meant to be secure.',
                    mitigation:'To mitigate this threat, a stronger cryptographic algorithm that is widely known to be secure should be used.  Currently, AES is one of the most secure encryption algorithms and is recommended to be used.   [33] [34]Environment (Platform Vulnerabilities)'});});

            flow.rule('Insecure Compiler Optimization', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '4.1',
                    title:'Insecure Compiler Optimization',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'Improperly scrubbing sensitive data from memory can compromise security.Compiler optimization errors occurs in the following scenarios:Secret data is stored in memory.The secret data is scrubbed from memory by overwriting its contents.The source code is compiled using an optimizing compiler, which identifies and removes the function that overwrites the contents as a dead store because the memory is not used subsequently.',
                    mitigation:'When writing code programmers must be aware of undefined and unstable behaviour that is defined within their code.  The main reason for this is compliers often remove code that they shouldn\\t which causes a system or an application more susceptible to security flaws and vulnerabilities.  In order to prevent the problem of optimization-unstable code programmers can use static checkers for identifying unstable code.  Static checkers like STACK developed by MIT works for checking C/C++ code, the Clang Static Analyzer works for checking C/C++/Objective-C programs, and PMD Java works for checking Java Source Code.  [3]'});});

            flow.rule('Insecure Transport', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '4.2',
                    title:'Insecure Transport',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'The application configuration should ensure that SSL is used for all access-controlled pages.If an application uses SSL to guarantee confidential communication with client browsers, the application configuration should make it impossible to view any access-controlled page without SSL. However, it is not an uncommon problem that the configuration of the application fails to enforce the use of SSL on pages that contain sensitive data.There are three common ways for SSL to be bypassed:A user manually enters the URL and types \"HTTP\" rather than \"HTTPS\".Attackers intentionally send a user to an insecure URL.A programmer erroneously creates a relative link to a page in the application, failing to switch from HTTP to HTTPS. (This is particularly easy to do when the link moves between public and secured areas on a web site.)',
                    mitigation:'The first and foremost control that needs to be applied is to check for a lack of transport encryption.  This can be done by:Reviewing network traffic of the device, its mobile application and any cloud connections to determine if any information is passed in clear textReviewing the use of SSL or TLS to ensure it is up to date and properly implementedReviewing the use of any encryption protocols to ensure they are recommended and acceptedIn order to ensure enough transport encryption:Ensuring data is encrypted using protocols such as SSL and TLS while transiting networks. Ensuring other industry standard encryption techniques are utilized to protect data during transport if SSL or TLS are not available. Ensuring only accepted encryption standards are used and avoid using proprietary encryption protocols. Ensuring the message payload encryptionEnsuring the secure encryption key handshaking. Ensuring received data integrity verification. [4]'});});

            flow.rule('Insufficient Session-ID Length', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '4.3',
                    title:'Insufficient Session-ID Length',
                    type:'Elevation of privilege',
                    status:'Open',
                    severity:'High',
                    description:'Session identifiers should be at least 128 bits long to prevent brute-force session guessing attacks. A shorter session identifier leaves the application open to brute-force session guessing attacks. If an attacker can guess or steal a session ID, then they may be able to take over the user\'s session (called session hijacking).  [7]',
                    mitigation:'Session identifiers should be at least 128 bits long to prevent brute-force session guessing.  Assume a 128-bit session identifier that provides 64 bits of entropy.  With a very large web site, an attacker might try 10,000 guesses per second with 100,000 valid session identifiers available to be guessed.  Given these assumptions, the expected time for an attacker to successfully guess a valid session identifier is greater than 292 years. A lower bound on the number of valid session identifiers that are available to be guessed is the number of users that are active on a site at any given moment.  However, any users that abandon their sessions without logging out will increase this number.  (This is one of many good reasons to have a short inactive session timeout. )[7]'});});

            flow.rule('Path Traversal', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '4.5',
                    title:'Path Traversal',
                    type:'Tampering',
                    status:'Open',
                    severity:'High',
                    description:'Allows attackers to access files that are not intended to be accessed. The software uses external input to construct a pathname that is intended to identify a file or directory that is located underneath a restricted parent directory, but the software does not properly neutralize special elements within the pathname that can cause the pathname to resolve to a location that is outside of the restricted directory. By using special elements such as \"..\" and \"/\" separators, attackers can escape outside of the restricted location to access files or directories that are elsewhere on the system. One of the most common special elements is the \"../\" sequence, which in most modern operating systems is interpreted as the parent directory of the current location. This is referred to as relative path traversal. Path traversal also covers the use of absolute pathnames such as \"/usr/local/bin\", which may also be useful in accessing unexpected files. This is referred to as absolute path traversal.[8]',
                    mitigation:'Input Validation: Assume all input is malicious.  Use an \"accept known good\" input validation strategy, i. e. , use a whitelist of acceptable inputs that strictly conform to specifications.  Reject any input that does not strictly conform to specifications or transform it into something that does.  When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules.  As an example of business rule logic, \"boat\" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as \"red\" or \"blue. \" Do not rely exclusively on looking for malicious or malformed inputs (i. e. , do not rely on a blacklist).  A blacklist is likely to miss at least one undesirable input, especially if the code\\s environment changes.  This can give attackers enough room to bypass the intended validation.  However, blacklists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright. Use a vetted library or framework that does not allow this weakness to occur or provides constructs that make this weakness easier to avoid. Use an application firewall that can detect attacks against this weakness.  It can be beneficial in cases in which the code cannot be fixed (because it is controlled by a third party), as an emergency prevention measure while more comprehensive software assurance measures are applied, or to provide defense in depth. Run your code using the lowest privileges that are required to accomplish the necessary tasks.  If possible, create isolated accounts with limited privileges that are only used for a single task.  That way, a successful attack will not immediately give the attacker access to the rest of the software or its environment.  For example, database applications rarely need to run as the database administrator, especially in day-to-day operations. Run the code in a \"jail\" or similar sandbox environment that enforces strict boundaries between the process and the operating system.  This may effectively restrict which files can be accessed in a directory or which command can be executed by the software.  OS-level examples include the Unix chroot jail, AppArmor, and SELinux.  In general, managed code may provide some protection.  For example, java. io. FilePermission in the Java SecurityManager allows the software to specify restrictions on file operations. Attack Surface Reduction: Store library, include, and utility files outside of the web document root, if possible.  Otherwise, store them in a separate directory and use the web server\\s access control capabilities to prevent attackers from directly requesting them.  One common practice is to define a fixed constant in each calling program, then check for the existence of the constant in the library/include file; if the constant does not exist, then the file was directly requested, and it can exit immediately.  This significantly reduces the chance of an attacker being able to bypass any protection mechanisms that are in the base program but not in the include files.  It will also reduce the attack surface. Ensure that error messages only contain minimal details that are useful to the intended audience, and nobody else.  The messages need to strike the balance between being too cryptic and not being cryptic enough.  They should not necessarily reveal the methods that were used to determine the error.  Such detailed information can be used to refine the original attack to increase the chances of success.  In the context of path traversal, error messages which disclose path information can help attackers craft the appropriate attack strings to move through the file system hierarchy. [8]'});});

            flow.rule('Exposure of Private Information (Privacy Violation)', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '4.6',
                    title:'Exposure of Private Information (Privacy Violation)',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'The software does not properly prevent private data (such as credit card numbers) from being accessed by actors who either (1) are not explicitly authorized to access the data or (2) do not have the implicit consent of the people to which the data is related. Mishandling private information, such as customer passwords or Social Security numbers, can compromise user privacy and is often illegal. An exposure of private information does not necessarily prevent the software from working properly, and in fact it might be intended by the developer, but it can still be undesirable (or explicitly prohibited by law) for the people who are associated with this private information. Some examples of private information include: social security numbers, web surfing history, credit card numbers, bank accounts, personal health records such as medical conditions, insurance information, prescription records, medical histories, test and laboratory results.[9]',
                    mitigation:'Separation of Privilege by compartmentalizing the system to have \"safe\" areas where trust boundaries can be unambiguously drawn.  Do not allow sensitive data to go outside of the trust boundary and always be careful when interfacing with a compartment outside of the safe area.  Ensure that appropriate compartmentalization is built into the system design and that the compartmentalization serves to allow for and further reinforce privilege separation functionality.  Architects and designers should rely on the principle of least privilege to decide when it is appropriate to use and to drop system privileges. Error Handling'});});

            flow.rule('Catch NullPointerException', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '5.1',
                    title:'Catch NullPointerException',
                    type:'Denial of service',
                    status:'Open',
                    severity:'Medium',
                    description:'It is generally a bad practice to catch NullPointerException. Programmers typically catch NullPointerException under three circumstances:The program contains a null pointer dereference. Catching the resulting exception was easier than fixing the underlying problem.The program explicitly throws a NullPointerException to signal an error condition.The code is part of a test harness that supplies unexpected input to the classes under test. This is the only acceptable scenario.[15]',
                    mitigation:'Do not extensively rely on catching exceptions (especially for validating user input) to handle errors.  Handling exceptions can decrease the performance of an application. [15]'});});

            flow.rule('Empty Catch Block', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '5.2',
                    title:'Empty Catch Block',
                    type:'Tampering',
                    status:'Open',
                    severity:'Medium',
                    description:'The software detects a specific error but takes no actions to handle the error.[16]',
                    mitigation:'Properly handle each exception.  This is the recommended solution.  Ensure that all exceptions are handled in such a way that you can be sure of the state of your system at any given moment. If a function returns an error, it is important to either fix the problem and try again, alert the user that an error has happened and let the program continue, or alert the user and close and cleanup the program. When testing subject, the software to extensive testing to discover some of the possible instances of where/how errors or return values are not handled.  Consider testing techniques such as ad hoc, equivalence partitioning, robustness and fault tolerance, mutation, and fuzzing. [16]'});});

            flow.rule('Missing Error Handling', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '5.3',
                    title:'Missing Error Handling',
                    type:'Spoofing',
                    status:'Open',
                    severity:'High',
                    description:'A web application must define a default error page for 404 errors, 500 errors, and to catch java.lang. Throwable exceptions prevent attackers from mining information from the application container\'s built-in error response. When an attacker explores a web site looking for vulnerabilities, the amount of information that the site provides is crucial to the eventual success or failure of any attempted attacks. If the application shows the attacker a stack trace, it relinquishes information that makes the attacker\'s job significantly easier. For example, a stack trace might show the attacker a malformed SQL query string, the type of database being used, and the version of the application container. This information enables the attacker to target known vulnerabilities in these components.[18]',
                    mitigation:'The application configuration should specify a default error page in order to guarantee that the application will never leak error messages to an attacker.  Handling standard HTTP error codes is useful and user-friendly in addition to being a good security practice, and a good configuration will also define a last-chance error handler that catches any exception that could possibly be thrown by the application. A specific policy for how to handle errors should be documented, including the types of errors to be handled and for each, what information is going to be reported back to the user, and what information is going to be logged.  All developers need to understand the policy and ensure that their code follows it. When errors occur, the site should respond with a specifically designed result that is helpful to the user without revealing unnecessary internal details.  Certain classes of errors should be logged to help detect implementation flaws in the site and/or hacking attempts.  Very few sites have any intrusion detection capabilities in their web application, but it is certainly conceivable that a web application could track repeated failed attempts and generate alerts. [19]'});});

            flow.rule('Return Inside Finally Block', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '5.4',
                    title:'Return Inside Finally Block',
                    type:'Denial of service',
                    status:'Open',
                    severity:'Low',
                    description:'The code has a return statement inside a finally block, which will cause any thrown exception in the try block to be discarded.[20]',
                    mitigation:'Do not use a return statement inside the finally block.  The finally block should have \"cleanup\" code. [20]'});});

            flow.rule('Unchecked Error Condition', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '5.5',
                    title:'Unchecked Error Condition',
                    type:'Tampering',
                    status:'Open',
                    severity:'Medium',
                    description:'Ignoring exceptions and other error conditions may allow an attacker to induce unexpected behavior unnoticed.[21]',
                    mitigation:'The choice between a language which has named, or unnamed exceptions needs to be done.  While unnamed exceptions exacerbate the chance of not properly dealing with an exception, named exceptions suffer from the up-call version of the weak base class problem. A language can be used which requires, at compile time, to catch all serious exceptions.  However, one must make sure to use the most current version of the API as new exceptions could be added. Catch all relevant exceptions.  This is the recommended solution.  Ensure that all exceptions are handled in such a way that you can be sure of the state of your system at any given moment. [21]Input Validation'});});

            flow.rule('Deserialization of Untrusted Data', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '6.1',
                    title:'Deserialization of Untrusted Data',
                    type:'Denial of service',
                    status:'Open',
                    severity:'Medium',
                    description:'The application deserializes untrusted data without sufficiently verifying that the resulting data will be valid. It is often convenient to serialize objects for communication or to save them for later use. However, deserialized data or code can often be modified without using the provided accessor functions if it does not use cryptography to protect itself.[22]',
                    mitigation:'If available, use the signing/sealing features of the programming language to assure that deserialized data has not been tainted.  For example, a hash-based message authentication code (HMAC) could be used to ensure that data has not been modified. When deserializing data, populate a new object rather than just deserializing.  The result is that the data flows through safe input validation and that the functions are safe. Explicitly define a final object() to prevent deserialization. Make fields transient to protect them from deserialization. An attempt to serialize and then deserialize a class containing transient fields will result in NULLs where the transient data should be. Avoid having unnecessary types or gadgets available that can be leveraged for malicious ends.  This limits the potential for unintended or unauthorized types and gadgets to be leveraged by the attacker.  Whitelist acceptable classes.  NOTE: This is alone is not a sufficient mitigation. [22]'});});

            flow.rule('Expression Language Injection', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '6.2',
                    title:'Expression Language Injection',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'Server-side code injection vulnerabilities arise when an application incorporates user-controllable data into a string that is dynamically evaluated by a code interpreter. If the user data is not strictly validated, an attacker can use crafted input to modify the code to be executed and inject arbitrary code that will be executed by the server. Server-side code injection vulnerabilities are usually very serious and lead to complete compromise of the application\'s data and functionality, and often of the server that is hosting the application. It may also be possible to use the server as a platform for further attacks against other systems.[23]',
                    mitigation:'Whenever possible, applications should avoid incorporating user-controllable data into dynamically evaluated code.  In almost every situation, there are safer alternative methods of implementing application functions, which cannot be manipulated to inject arbitrary code into the server\\s processing. If it is considered unavoidable to incorporate user-supplied data into dynamically evaluated code, then the data should be strictly validated.  Ideally, a whitelist of specific accepted values should be used.  Otherwise, only short alphanumeric strings should be accepted.  Input containing any other data, including any conceivable code metacharacters, should be rejected. [23]'});});

            flow.rule('Form Action Hijacking', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '6.3',
                    title:'Form Action Hijacking',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'Medium',
                    description:'Form action hijacking vulnerabilities arise when an application places user-supplied input into the action URL of an HTML form. An attacker can use this vulnerability to construct a URL that, if visited by another application user, will modify the action URL of a form to point to the attacker\'s server. If a user submits the form then its contents, including any input from the victim user, will be delivered directly to the attacker. Even if the user doesn\'t enter any sensitive information, the form may still deliver a valid CSRF token to the attacker, enabling them to perform CSRF attacks. In some cases, web browsers may help exacerbate this issue by autocompleting forms with previously entered user input.[24]',
                    mitigation:'Consider hard-coding the form action URL or implementing a whitelist of allowed values. [24]'});});

            flow.rule('Improper Input Validation', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '6.4',
                    title:'Improper Input Validation',
                    type:'Tampering',
                    status:'Open',
                    severity:'High',
                    description:'The product does not validate or incorrectly validates input that can affect the control flow or data flow of a program. When software does not validate input properly, an attacker is able to craft the input in a form that is not expected by the rest of the application. This will lead to parts of the system receiving unintended input, which may result in altered control flow, arbitrary control of a resource, or arbitrary code execution.[25]',
                    mitigation:'Use an input validation framework such as Struts or the OWASP ESAPI Validation API.  If you use Struts, be mindful of Struts Validation ProblemsUnderstand all the potential areas where untrusted inputs can enter your software: parameters or arguments, cookies, anything read from the network, environment variables, reverse DNS lookups, query results, request headers, URL components, e-mail, files, filenames, databases, and any external systems that provide data to the application.  Remember that such inputs may be obtained indirectly through API calls. Assume all input is malicious.  Use an \"accept known good\" input validation strategy, i. e. , use a whitelist of acceptable inputs that strictly conform to specifications.  Reject any input that does not strictly conform to specifications or transform it into something that does.  When performing input validation, consider all potentially relevant properties, including length, type of input, the full range of acceptable values, missing or extra inputs, syntax, consistency across related fields, and conformance to business rules.  As an example of business rule logic, \"boat\" may be syntactically valid because it only contains alphanumeric characters, but it is not valid if the input is only expected to contain colors such as \"red\" or \"blue. \" Do not rely exclusively on looking for malicious or malformed inputs (i. e. , do not rely on a blacklist).  A blacklist is likely to miss at least one undesirable input, especially if the code\\s environment changes.  This can give attackers enough room to bypass the intended validation.  However, blacklists can be useful for detecting potential attacks or determining which inputs are so malformed that they should be rejected outright. For any security checks that are performed on the client side, ensure that these checks are duplicated on the server side, in order to avoid client-side enforcement of server-side securityAttackers can bypass the client-side checks by modifying values after the checks have been performed, or by changing the client to remove the client-side checks entirely.  Then, these modified values would be submitted to the server. Use dynamic tools and techniques that interact with the software using large test suites with many diverse inputs, such as fuzz testing (fuzzing), robustness testing, and fault injection. Use tools and techniques that require manual (human) analysis, such as penetration testing, threat modeling, and interactive tools that allow the tester to record and modify an active session[25]'});});

            flow.rule('Missing XML Validation', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '6.5',
                    title:'Missing XML Validation',
                    type:'Tampering',
                    status:'Open',
                    severity:'High',
                    description:'The software accepts XML from an untrusted source but does not validate the XML against the proper schema. Most successful attacks begin with a violation of the programmer\'s assumptions. By accepting an XML document without validating it against a DTD or XML schema, the programmer leaves a door open for attackers to provide unexpected, unreasonable, or malicious input.[36]',
                    mitigation:'Always validate XML input against a known XML Schema or DTD. It is not possible for an XML parser to validate all aspects of a document\\s content because a parser cannot understand the complete semantics of the data.  However, a parser can do a complete and thorough job of checking the document\\s structure and therefore guarantee to the code that processes the document that the content is well-formed. [36]'});});

            flow.rule('Overly Permissive Regular Expression', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '6.6',
                    title:'Overly Permissive Regular Expression',
                    type:'Elevation of privilege',
                    status:'Open',
                    severity:'High',
                    description:'The product uses a regular expression that does not sufficiently restrict the set of allowed values. [38]',
                    mitigation:'To mitigate this threat, where possible, ensure that the regular expressions does a check to see where the start and end string patterns are.  As well there should be a restriction to limit the number of characters in a given string that the regular expression will check. [38] [39]'});});

            flow.rule('Process Control', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '6.7',
                    title:'Process Control',
                    type:'Denial of service',
                    status:'Open',
                    severity:'Medium',
                    description:'Executing commands or loading libraries from an untrusted source or in an untrusted environment can cause an application to execute malicious commands (and payloads) on behalf of an attacker. Process control vulnerabilities take two forms: An attacker can change the command that the program executes by explicitly controlling what the command is. An attacker can change the environment in which the command executes by implicitly controlling what the command means. Process control vulnerabilities of the first type occur when either data enters the application from an untrusted source and the data is used as part of a string representing a command that is executed by the application. By executing the command, the application gives an attacker a privilege or capability that the attacker would not otherwise have.[37]',
                    mitigation:'Libraries that are loaded should be well understood and come from a trusted source.  The application can execute code contained in the native libraries, which often contain calls that are susceptible to other security problems, such as buffer overflows or command injection.  All native libraries should be validated to determine if the application requires the use of the library.  It is very difficult to determine what these native libraries do, and the potential for malicious code is high.  In addition, the potential for an inadvertent mistake in these native libraries is also high, as many are written in C or C++ and may be susceptible to buffer overflow or race condition problems.  To help prevent buffer overflow attacks, validate all input to native calls for content and length.  If the native library does not come from a trusted source, review the source code of the library.  The library should be built from the reviewed source before using it. [37]'});});

            flow.rule('String Termination Error', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '6.8',
                    title:'String Termination Error',
                    type:'Denial of service',
                    status:'Open',
                    severity:'Medium',
                    description:'Relying on proper string termination may result in a buffer overflow.String termination errors occur when:Data enters a program via a function that does not null terminate its output.The data is passed to a function that requires its input to be null terminated.[41]',
                    mitigation:'Use a language that is not susceptible to these issues.  However, be careful of null byte interaction errors with lower-level constructs that may be written in a language that is susceptible. Ensure that all string functions used are understood fully as to how they append null characters.  Also, be wary of off-by-one errors when appending nulls to the end of strings. If performance constraints permit, special code can be added that validates null-termination of string buffers, this is a rather naive and error-prone solution. Switch to bounded string manipulation functions.  Inspect buffer lengths involved in the buffer overrun trace reported with the defect. Add code that fills buffers with nulls (however, the length of buffers still needs to be inspected, to ensure that the non-null-terminated string is not written at the physical end of the buffer). Visit the following pages for more information for mitigation strategies for strings in C and C++:http://www. informit. com/articles/article. aspx?p=2036582&seqNum=4https://www. synopsys. com/blogs/software-security/detect-prevent-and-mitigate-buffer-overflow-attacks/[41]'});});

            flow.rule('Unchecked Return Value', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '6.9',
                    title:'Unchecked Return Value',
                    type:'Tampering',
                    status:'Open',
                    severity:'Low',
                    description:'The software does not check the return value from a method or function, which can prevent it from detecting unexpected states and conditions. Two common programmer assumptions are \"this function call can never fail\" and \"it doesn\'t matter if this function call fails\". If an attacker can force the function to fail or otherwise return a value that is not expected, then the subsequent program logic could lead to a vulnerability, because the software is not in a state that the programmer assumes. For example, if the program calls a function to drop privileges but does not check the return code to ensure that privileges were successfully dropped, then the program will continue to operate with the higher privileges. [40]',
                    mitigation:'To mitigate this threat, three techniques must be applied to all functions in the given program that is being evaluated:Ensure all of the functions that return a value, actually return a value and confirm that the value is expected. Ensure within each function, that the possible of return values are coveredWithin each function, ensure that there is a check/default value when there is an error.  [40]'});});

            flow.rule('Unsafe JNI', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '6.10',
                    title:'Unsafe JNI',
                    type:'Denial of service',
                    status:'Open',
                    severity:'Low',
                    description:'When a Java application uses the Java Native Interface (JNI) to call code written in another programming language, it can expose the application to weaknesses in that code, even if those weaknesses cannot occur in Java. Many safety features that programmers may take for granted simply do not apply for native code, so you must carefully review all such code for potential problems. The languages used to implement native code may be more susceptible to buffer overflows and other attacks. Native code is unprotected by the security features enforced by the runtime environment, such as strong typing and array bounds checking [42]',
                    mitigation:'To mitigate this threat, three techniques must be applied in the given program that is being evaluated:Implement a form of error handling within each JNI call. Avoid using any JNI calls if the native library is untrusted. Seek an alternative to a JNI call such as using a Java API. '});});

            flow.rule('Unsafe use of reflection', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '6.11',
                    title:'Unsafe use of reflection',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'Medium',
                    description:'This vulnerability is caused by unsafe use of the reflection mechanisms in programming languages like Java, C#, or Ruby, etc. An attacker may be able to create unexpected control flow paths through the application, potentially bypassing security checks. Exploitation of this weakness can result in a limited form of code injection. If an attacker can supply values that the application then uses to determine which class to instantiate or which method to invoke, the potential exists for the attacker to create control flow paths through the application that were not intended by the application developers. This attack vector may allow the attacker to bypass authentication or access control checks or otherwise cause the application to behave in an unexpected manner. This situation becomes a doomsday scenario if the attacker can upload files into a location that appears on the application\'s classpath or add new entries to the application\'s classpath. Under either of these conditions, the attacker can use reflection to introduce new, presumably malicious, behavior into the application.[43]',
                    mitigation:'Refactor your code to avoid using reflection. Do not use user-controlled inputs to select and load classes or code. Apply strict input validation by using whitelists or indirect selection to ensure that the user is only selecting allowable classes or code. [43]Session Management'});});

            flow.rule('Session Variable Overloading', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '7.1',
                    title:'Session Variable Overloading',
                    type:'Spoofing',
                    status:'Open',
                    severity:'Low',
                    description:'Session Variable Overloading (also known as Session Puzzling) is an application level vulnerability which can enable an attacker to perform a variety of malicious actions not limited to:Bypass efficient authentication enforcement mechanisms, and impersonate legitimate users.Elevate the privileges of a malicious user account, in an environment that would otherwise be considered foolproof.Skip over qualifying phases in multiphase processes, even if the process includes all the commonly recommended code level restrictions.Manipulate server-side values in indirect methods that cannot be predicted or detected.Execute traditional attacks in locations that were previously unreachable, or even considered secure.This vulnerability occurs when an application uses the same session variable for more than one purpose. An attacker can potentially access pages in an order unanticipated by the developers so that the session variable is set one context and then used in another [44]',
                    mitigation:'To mitigate this threat, the use of session variables should be restricted, where they are used for one consistent purpose [44]. Mobile Risk *(separate)'});});

            flow.rule('Weak Server Side Controls', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.1',
                    title:'Weak Server Side Controls',
                    type:'Tampering',
                    status:'Open',
                    severity:'Medium',
                    description:'Any entity that acts as a source of untrustworthy input to a backend API service, web service, or traditional web server application. Examples of such entities include: a user, malware, or a vulnerable app on the mobile device [45]',
                    mitigation:'To mitigate this threat, secure coding and proper configurations must be used on the server side of the mobile application.  [45]'});});

            flow.rule('Insecure Data Storage', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.2',
                    title:'Insecure Data Storage',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'An adversary that has attained a lost/stolen mobile device; malware or another repackaged app acting on the adversary\'s behalf that executes on the mobile device. If an adversary physically attains the mobile device, the adversary hooks up the mobile device to a computer with freely available software. These tools allow the adversary to see all third party application directories that often contain stored personally identifiable information (PII), or personal health records (PHR). An adversary may construct malware or modify a legitimate app to steal such information assets.[46]',
                    mitigation:'It is important to threat model your mobile app, OS, platforms and frameworks to understand the information assets the app processes and how the APIs handle those assets.  Determine how your application or software handles the following information:URL caching (both request and response);Keyboard press caching;Copy/Paste buffer caching;Application backgrounding;Intermediate dataLogging;HTML5 data storage;Browser cookie objects;Analytics data sent to 3rd parties. [46]'});});

            flow.rule('Improper Platform Usage', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.3',
                    title:'Improper Platform Usage',
                    type:'Tampering',
                    status:'Open',
                    severity:'Medium',
                    description:'This category covers misuse of a platform feature or failure to use platform security controls. It might include Android intents, platform permissions, misuse of TouchID, the Keychain, or some other security control that is part of the mobile operating system. The defining characteristic of risks in this category is that the platform (iOS, Android, Windows Phone, etc.) provides a feature or a capability that is documented and well understood. The app fails to use that capability or uses it incorrectly. This differs from other mobile top ten risks because the design and implementation is not strictly the app developer\'s issue.There are several ways that mobile apps can experience this risk.Violation of published guidelines. All platforms have development guidelines for security (((Android)), ((iOS)), ((Windows Phone))). If an app contradicts the best practices recommended by the manufacturer, it will be exposed to this risk. For example, there are guidelines on how to use the iOS Keychain or how to secure exported services on Android. Apps that do not follow these guidelines will experience this risk.Violation of convention or common practice: Not all best practices are codified in manufacturer guidance. In some instances, there are de facto best practices that are common in mobile apps.Unintentional Misuse: Some apps intend to do the right thing but get some part of the implementation wrong. This could be a simple bug, like setting the wrong flag on an API call, or it could be a misunderstanding of how the protections work.  [47]',
                    mitigation:'To mitigate this threat, secure coding and proper configurations must be used on the server side of the mobile application [47]. '});});

            flow.rule('Improper Platform Usage', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.4',
                    title:'Improper Platform Usage',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'When designing a mobile application, data is commonly exchanged in a client-server fashion. When the solution transmits its data, it must traverse the mobile device\'s carrier network and the internet. Attackers may exploit these vulnerabilities to intercept sensitive data such as: social security numbers, web surfing history, credit card numbers, bank accounts, personal health records such as medical conditions, insurance information, prescription records, medical histories, test and laboratory result while travelling across the wire.[48]',
                    mitigation:'Assume that the network layer is not secure and is susceptible to eavesdropping. Apply SSL/TLS to transport channels that the mobile app will use to transmit sensitive information, session tokens, or other sensitive data to a backend API or web service. Account for outside entities like third-party analytics companies, social networks, etc.  by using their SSL versions when an application runs a routine via the browser/webkit.  Avoid mixed SSL sessions as they may expose the user\\s session ID. Use strong, industry standard cipher suites with appropriate key lengths. Use certificates signed by a trusted CA provider. Never allow self-signed certificates and consider certificate pinning for security conscious applications. Always require SSL chain verification. Only establish a secure connection after verifying the identity of the endpoint server using trusted certificates in the key chain. Alert users through the UI if the mobile app detects an invalid certificate. Do not send sensitive data over alternate channels (e. g.  SMS, MMS, or notifications). If possible, apply a separate layer of encryption to any sensitive data before it is given to the SSL channel.  If future vulnerabilities are discovered in the SSL implementation, the encrypted data will provide a secondary defense against confidentiality violation. [48]'});});

            flow.rule('Insecure Authentication', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.5',
                    title:'Insecure Authentication',
                    type:'Tampering',
                    status:'Open',
                    severity:'High',
                    description:'Authentication vulnerabilities are exploited through automated attacks that use available or custom-built tools. Once the adversary understands how the authentication scheme is vulnerable, they fake or bypass authentication by submitting service requests to the mobile app\'s backend server and bypass any direct interaction with the mobile app. This submission process is typically done via mobile malware within the device or botnets owned by the attacker.[49]',
                    mitigation:'Avoid weak authentication patterns:If you are porting a web application to its mobile equivalent, authentication requirements of mobile applications should match that of the web application component.  Therefore, it should not be possible to authenticate with less authentication factors than the web browser;Authenticating a user locally can lead to client-side bypass vulnerabilities.  If the application stores data locally, the authentication routine can be bypassed on jailbroken devices through run-time manipulation or modification of the binary.  If there is a compelling business requirement for offline authentication, see M10 for additional guidance on preventing binary attacks against the mobile app;Where possible, ensure that all authentication requests are performed server-side.  Upon successful authentication, application data will be loaded onto the mobile device.  This will ensure that application data will only be available after successful authentication;If client-side storage of data is required, the data will need to be encrypted using an encryption key that is securely derived from the user\\s login credentials.  This will ensure that the stored application data will only be accessible upon successfully entering the correct credentials.  There are additional risks that the data will be decrypted via binary attacks.  See M9 for additional guidance on preventing binary attacks that lead to local data theft;Persistent authentication (Remember Me) functionality implemented within mobile applications should never store a user\\s password on the device;Ideally, mobile applications should utilize a device-specific authentication token that can be revoked within the mobile application by the user.  This will ensure that the app can mitigate unauthorized access from a stolen/lost device;Do not use any spoof-able values for authenticating a user.  This includes device identifiers or geo-location;Persistent authentication within mobile applications should be implemented as opt-in and not be enabled by default;If possible, do not allow users to provide 4-digit PIN numbers for authentication passwords. Reinforce Authentication:Developers should assume all client-side authorization and authentication controls can be bypassed by malicious users.  Authorization and authentication controls must be re-enforced on the server-side whenever possible. Due to offline usage requirements, mobile apps may be required to perform local authentication or authorization checks within the mobile app\\s code.  If this is the case, developers should instrument local integrity checks within their code to detect any unauthorized code changes.  See M9 for more information about detecting and reacting to binary attacks. [49]'});});

            flow.rule('Insecure Authorization', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.6',
                    title:'Insecure Authorization',
                    type:'Elevation of privilege',
                    status:'Open',
                    severity:'High',
                    description:'Authorization vulnerabilities are exploited through automated attacks that use available or custom-built tools. Once the adversary understands how the authorization scheme is vulnerable, they login to the application as a legitimate user. They successfully pass the authentication control. Once past authentication, they typically force-browse to a vulnerable endpoint to execute administrative functionality. This submission process is typically done via mobile malware within the device or botnets owned by the attacker. [50]',
                    mitigation:'To mitigate this threat, two methods are suggested.  Firstly, ensure the roles and permissions of the authenticated can be confirmed using the information from a backend system.  Lastly, the code from the back end should be able to identify a request from a user and match it to a user\\s profile that is stored in the backend [50]'});});

            flow.rule('Insufficient Transport Layer Protection', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.7',
                    title:'Insufficient Transport Layer Protection',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'Medium',
                    description:'When designing a mobile application, data is commonly exchanged in a client-server fashion. When the solution transmits its data, it must traverse the mobile device\'s carrier network and the internet. Threat agents might exploit vulnerabilities to intercept sensitive data while it\'s traveling across the wire. The following ways are possible threat agents that exist:An adversary that shares your local network (compromised or monitored Wi-Fi);Carrier or network devices (routers, cell towers, proxy\'s, etc.); orMalware on your mobile device.[51]',
                    mitigation:'General Best Practices:Assume that the network layer is not secure and is susceptible to eavesdropping. Apply SSL/TLS to transport channels that the mobile app will use to transmit sensitive information, session tokens, or other sensitive data to a backend API or web service. Account for outside entities like third-party analytics companies, social networks, etc.  by using their SSL versions when an application runs a routine via the browser\\s webkit.  Avoid mixed SSL sessions as they may expose the user\\s session ID. Use strong, industry standard cipher suites with appropriate key lengths. Use certificates signed by a trusted CA provider. Never allow self-signed certificates and consider certificate pinning for security conscious applications. Always require SSL chain verification. Only establish a secure connection after verifying the identity of the endpoint server using trusted certificates in the key chain. Alert users through the UI if the mobile app detects an invalid certificate. Do not send sensitive data over alternate channels (e. g, SMS, MMS, or notifications). If possible, apply a separate layer of encryption to any sensitive data before it is given to the SSL channel.  In the event that future vulnerabilities are discovered in the SSL implementation, the encrypted data will provide a secondary defense against confidentiality violation. iOS Specific Best Practices:Default classes in the latest version of iOS handle SSL cipher strength negotiation very well.  Trouble comes when developers temporarily add code to bypass these defaults to accommodate development hurdles.  In addition to the above general practices:Ensure that certificates are valid and fail closed. When using CFNetwork, consider using the Secure Transport API to designate trusted client certificates.  In almost all situations, NSStreamSocketSecurityLevelTLSv1 should be used for higher standard cipher strength. After development, ensure all NSURL calls (or wrappers of NSURL) do not allow self-signed or invalid certificates such as the NSURL class method setAllowsAnyHTTPSCertificate. Consider using certificate pinning by doing the following: export your certificate, include it in your app bundle, and anchor it to your trust object.  Using the NSURL method connection:willSendRequestForAuthenticationChallenge: will now accept your cert. Android Specific Best Practices:Remove all code after the development cycle that may allow the application to accept all certificates such as org. apache. http. conn. ssl. AllowAllHostnameVerifier or SSLSocketFactory. ALLOW_ALL_HOSTNAME_VERIFIER.  These are equivalent to trusting all certificates. If using a class which extends SSLSocketFactory, make sure checkServerTrusted method is properly implemented so that server certificate is correctly checked. [51]'});});

            flow.rule('Unintended Data Leakage', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.8',
                    title:'Unintended Data Leakage',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'Unintended data leakage occurs when a developer inadvertently places sensitive information or data in a location on the mobile device that is easily accessible by other apps on the device. This vulnerability is exploited by mobile malware, modified versions of legitimate apps, or an adversary that has physical access to the victim\'s mobile device. In case the attacker has physical access to the device, then the attacker can use freely available forensic tools to conduct an attack. Another possible attack vector would be if an attacker has access to the device via malicious code, so they will use fully permissible and documented API calls to conduct an attack. [51]',
                    mitigation:'Threat model your OS, platforms, and frameworks to determine how they handle the following features:URL Caching (Both request and response)Keyboard Press CachingCopy/Paste buffer CachingApplication backgroundingLoggingHTML5 data storageBrowser cookie objectsAnalytics data sent to 3rd partiesAlso identify what a given OS or framework does by default, by doing this and applying mitigating controls, unintended data leakage can be avoided.  [51]'});});

            flow.rule('Broken/Insecure Cryptography', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.9',
                    title:'Broken/Insecure Cryptography',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'This threat is cause when an adversary has physical access to data that has been encrypted improperly, or mobile malware acting on an adversary\'s behalf. This can be done in several ways such as decryption access to the device or network traffic capture, or malicious apps on the device with access to the encrypted data Hello.',
                    mitigation:'To mitigate this threat, avoid using algorithms or protocols that are unsecure such as \RC2\, \MD4\, \MD5\ and \SHA1\.  A stronger cryptographic algorithm that is widely known to be secure should be used.  Currently, AES is one of the most secure encryption algorithms and is recommended to be used.   [33] [34] [52]'});});

            flow.rule('Client-Side Injection', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.10',
                    title:'Client-Side Injection',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'Medium',
                    description:'Client-side injection results in the execution of malicious code on the mobile device via the mobile app. Consider anyone who can send untrusted data to the mobile app, including external users, internal users, the application itself or other malicious apps on the mobile device. A possible attack vector could be an adversary loads simple text-based attacks that exploit the syntax of the targeted interpreter within the mobile app. It is important to understand that almost any source of data can be an injection vector, including resource files or the application itself. [53]',
                    mitigation:'IOS Specific Best Practices:SQLite Injection: When designing queries for SQLite be sure that user supplied data is being passed to a parameterized query.  This can be spotted by looking for the format specifier used.  In general, dangerous user supplied data will be inserted by a %@ instead of a proper parameterized query specifier of?. JavaScript Injection (XSS, etc): Ensure that all UIWebView calls do not execute without proper input validation.  Apply filters for dangerous JavaScript characters if possible, using a whitelist over blacklist character policy before rendering.  If possible, call mobile Safari instead of rending inside of UIWebkit which has access to your application. Local File Inclusion: Use input validation for NSFileManager calls. XML Injection: use libXML2 over NSXMLParserFormat String Injection: Several Objective C methods are vulnerable to format string attacks:NSLog, [NSString stringWithFormat:], [NSString initWithFormat:], [NSMutableString appendFormat:], [NSAlert informativeTextWithFormat:], [NSPredicate predicateWithFormat:], [NSException format:], NSRunAlertPanel. Do not let sources outside of your control, such as user data and messages from other applications or web services, control any part of your format strings. Classic C Attacks: Objective C is a superset of C, avoid using old C functions vulnerable to injection such as: strcat, strcpy, strncat, strncpy, sprint, vsprintf, gets, etc. Android Specific Best Practices:SQL Injection: When dealing with dynamic queries or Content-Providers ensure you are using parameterized queries. JavaScript Injection (XSS): Verify that JavaScript and Plugin support is disabled for any WebViews (usually the default). Local File Inclusion: Verify that File System Access is disabled for any WebViews (webview. getSettings(). setAllowFileAccess(false);). Intent Injection\/Fuzzing: Verify actions and data are validated via an Intent Filter for all Activities. Binary Injection\/Modification Prevention for Android and iOS:Follow security coding techniques for jailbreak detection, checksum, certificate pinning, and debugger detection controlsThe organization building the app must adequately prevent an adversary from analyzing and reverse engineering the app using static or dynamic analysis techniques. The mobile app must be able to detect at runtime that code has been added or changed from what it knows about its integrity at compile time.  The app must be able to react appropriately at runtime to a code integrity violation. [53]'});});

            flow.rule('Poor Client Code Quality', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.11',
                    title:'Poor Client Code Quality',
                    type:'Spoofing',
                    status:'Open',
                    severity:'Medium',
                    description:'This threat involves entities that can pass untrusted inputs to method calls made within mobile code. These types of issues are not necessarily security issues in and of themselves but lead to security vulnerabilities. For example, buffer overflows within older versions of Safari (a poor code quality vulnerability) led to high risk drive-by Jailbreak attacks. Poor code-quality issues are typically exploited via malware or phishing scams. An attacker will typically exploit vulnerabilities in this category by supplying carefully crafted inputs to the victim. These inputs are passed onto code that resides within the mobile device where exploitation takes place. Typical types of attacks will exploit memory leaks and buffer overflows.[54]',
                    mitigation:'To mitigate this threat, the following countermeasures should be considered:Consistent coding patterns, standards in an organizationWrite code that is legible and documentedAny code that requires a buffer, the length of the input should be checked, and the length should be restricted. Use third party tools to find buffer overflows and memory leaks. Prioritize to fix any buffer overflows and memory leaks that are present in the code before moving on to other issues. '});});

            flow.rule('Code Tampering', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.12',
                    title:'Code Tampering',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'High',
                    description:'Typically, an attacker will exploit code modification via malicious forms of the apps hosted in third-party app stores. The attacker may also trick the user into installing the app via phishing attacks. Possible attack vectors include:Make direct binary changes to the application package\'s core binaryMake direct binary changes to the resources within the application\'s packageRedirect or replace system APIs to intercept and execute foreign code that is malicious[55]',
                    mitigation:'The mobile app must be able to detect at runtime that code has been added or changed from what it knows about its integrity at compile time.  The app must be able to react appropriately at runtime to a code integrity violation. Android Root Detection:Typically, an app that has been modified will execute within a Jailbroken or rooted environment.  As such, it is reasonable to try and detect these types of compromised environments at runtime and react accordingly (report to the server or shutdown).  There are a few common ways to detect a rooted Android device:Check for test-keys to see if build. prop includes the line ro. build. tags=test-keys indicating a developer build or unofficial ROMCheck for OTA certificates to see if the file /etc/security/otacerts. zip existsCheck for several known rooted apk\\s such as: com. noshufou. android. su,  com. thirdparty. superuser, eu. chainfire. supersu, com. koushikdutta. superuserCheck for SU binaries in: /system/bin/su, /system/xbin/su, /sbin/su, /system/su, /system/bin/. ext/. suAttempt SU command directly by running the command su and check the id of the current user, if it returns 0 then the su command has been successfulIOS Jailbreak Detection:Visit the following page for more information:[55]'});});

            flow.rule('Reverse Engineering', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.13',
                    title:'Reverse Engineering',
                    type:'Information disclosure',
                    status:'Open',
                    severity:'Medium',
                    description:'This threat involves attackers who will download the targeted app from an app store and analyze it within their own local environment using a suite of different tools. An attacker must perform an analysis of the final core binary to determine its original string table, source code, libraries, algorithms, and resources embedded within the app. Attackers will use relatively affordable and well-understood tools like IDA Pro, Hopper, otool, strings, and other binary inspection tools from within the attacker\'s environment.  [56]',
                    mitigation:'To mitigate this threat, an obfuscation tool must be used.  This tool will have the following features:Narrow down what methods / code segments to obfuscate;Tune the degree of obfuscation to balance performance impact;Withstand de-obfuscation from tools like IDA Pro and Hopper;Obfuscate string tables as well as methodsA few suggested tools to use are IDA Pro and Hopper [56]. '});});

            flow.rule('Extraneous Functionality', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.14',
                    title:'Extraneous Functionality',
                    type:'Repudiation',
                    status:'Open',
                    severity:'High',
                    description:'Typically, an attacker seeks to understand extraneous functionality within a mobile app in order to discover hidden functionality in in backend systems. The attacker will typically exploit extraneous functionality directly from their own systems without any involvement by end-users. An attacker will download and examine the mobile app within their own local environment. They will examine log files, configuration files, and perhaps the binary itself to discover any hidden switches or test code that was left behind by the developers. [57]',
                    mitigation:'Best way to prevent this vulnerability is to perform manual secure code review using security champs or subject matter experts most knowledgeable with this code.   This should be done by:Examine the app\\s configuration settings to discover any hidden switches;Verify that all test code is not included in the final production build of the app;Examine all API endpoints accessed by the mobile app to verify that these endpoints are well documented and publicly available;Examine all log statements to ensure nothing overly descriptive about the backend is being written to the logs[57]'});});

            flow.rule('Unintended Data Leakage', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.15',
                    title:'Unintended Data Leakage',
                    type:'Tampering',
                    status:'Open',
                    severity:'High',
                    description:'This threat involves entities that can pass untrusted inputs to the sensitive method calls. Examples of such entities include, but are not limited to, users, malware and vulnerable apps  An attacker with access to app can intercept intermediate calls and manipulate results via parameter tampering. [58]',
                    mitigation:'To mitigate this threat, avoid using depreciated/unsupported methods for each platform that the application is being used.  As an example, for iOS, avoid using the handleOpenURL method to process URL scheme calls.  Find an alternative method that is supported by the platform [58]. '});});

            flow.rule('Improper Session Handling', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({ ruleId: '8.16',
                    title:'Improper Session Handling',
                    type:'Spoofing',
                    status:'Open',
                    severity:'High',
                    description:'Anyone or any mobile app with access to HTTP/S traffic, cookie data, etc.  Possible attack vectors include physical access to the device, and network traffic capture, or malware on the mobile device. Essentially an adversary that has access to the session tokens can impersonate the user by submitting the token to the backend server for any sensitive transactions such as credit card payments or health information like EKG results sent to a doctor. [59]',
                    mitigation:'Validate sessions on the backend by ensuring all session invalidation events are executed on the server side and not just on the mobile app. Add adequate timeout protection to prevent the malicious potential for an unauthorized user to gain access to an existing session and assume the role of that user.  Timeout periods vary accordingly based on the application, but some good guidelines are: 15 minutes for high security apps, 30 minutes for medium security apps, and 1 hour for low security apps. Properly reset cookies during authentication state changes, by destroying sessions on the server side and making sure that the cookies presented as a part of the previous sessions are no longer acceptedIn addition to properly invalidating tokens on the server side during key application events, make sure tokens are generated properly by using well-established and industry standard methods of creating tokens.  Visit the following websites for more details: https://www. pcisecuritystandards. org/documents/Tokenization_Product_Security_Guidelines. pdf and https://tools. ietf. org/html/rfc7519 for JSON Web Token (JWT) and https://www. ietf. org/rfc/rfc6750. txt for Bearer Token Usage[59]'});});


        });
    }
}

module.exports = threatengine;