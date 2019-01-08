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
            flow.rule('Empty String Password', [[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials)'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '1.1',
                        title:'Empty String Password',
                        type:'Information disclosure',
                        status:'Open',
                        severity:'High',
                        description:'Using an empty string as a password is insecure. It is never appropriate to use an empty string as a password.  It is too easy to guess.  An empty string password makes the authentication as weak as the user names, which are normally public or guessable.  This makes a brute-force attack against the login interface much easier. '});

            flow.rule('Password in Configuration File', [[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials)'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '1.2',
                        title:'Password in Configuration File',
                        type:'Information disclosure',
                        status:'Open',
                        severity:'Medium',
                        description:'Storing a password in a configuration file allows anyone who can read the file access to the password-protected resource.  Developers sometimes believe that they cannot defend the application from someone who has access to the configuration, but this attitude makes an attacker\s job easier. '});

            flow.rule('Hardcoded Password', [[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials)'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '1.3',
                        title:'Hardcoded Password',
                        type:'Information disclosure',
                        status:'Open',
                        severity:'High',
                        description:'Hardcoded passwords may compromise system security in a way that cannot be easily remedied. It is never a good idea to hardcode a password.  Not only does hardcoding a password allow all the project\\s developers to view the password, it also makes fixing the problem extremely difficult.  Once the code is in production, the password cannot be changed without patching the software.  If the account protected by the password is compromised, the owners of the system will be forced to choose between security and availability. '});

            flow.rule('Password Plaintext Storage', [[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.storesCredentials)'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '1.4',
                        title:'Password Plaintext Storage',
                        type:'Information disclosure',
                        status:'Open',
                        severity:'High',
                        description:'Storing a password in plaintext may result in a system compromise. Password management issues occur when a password is stored in plaintext in an application\s properties or configuration file.  A programmer can attempt to remedy the password management problem by obscuring the password with an encoding function, such as base 64 encoding, but this effort does not adequately protect the password. '});

            flow.rule('Least Privilege Violation', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '1.5',
                        title:'Least Privilege Violation',
                        type:'Elevation of privilege',
                        status:'Open',
                        severity:'Medium',
                        description:'The elevated privilege level required to perform operations such as chroot() should be dropped immediately after the operation is performed. When a program calls a privileged function, such as chroot(), it must first acquire root privilege.  As soon as the privileged operation has completed, the program should drop root privilege and return to the privilege level of the invoking user. '});

            flow.rule('Code Permission', [[Element, 'el','el.element.attributes.type == "tm.Actor"'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '1.6',
                        title:'Code Permission',
                        type:'Tampering',
                        status:'Open',
                        severity:'High',
                        description:'An active developer with access to unrelated module code may tamper or disclose sensitive project information (Interproject Code Access). Code Quality'});

            flow.rule('Double Free Error', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '2.1',
                        title:'Double Free Error',
                        type:'Tampering',
                        status:'Open',
                        severity:'High',
                        description:'Double free errors occur when free() is called more than once with the same memory address as an argument. Calling free() twice on the same value can lead to memory leak.  When a program calls free() twice with the same argument, the program\s memory management data structures become corrupted and could allow a malicious user to write values in arbitrary memory spaces.  This corruption can cause the program to crash or, in some circumstances, alter the execution flow.  By overwriting registers or memory spaces, an attacker can trick the program into executing code of his/her own choosing, often resulting in an interactive shell with elevated permissions. When a buffer is free()\d, a linked list of free buffers is read to rearrange and combine the chunks of free memory (to be able to allocate larger buffers in the future).  These chunks are laid out in a double linked list which points to previous and next chunks.  Unlinking an unused buffer (which is what happens when free() is called) could allow an attacker to write arbitrary values in memory; essentially overwriting valuable registers, calling shellcode from its own buffer. (Double Free Suggestion) Implementation: Ensure that each allocation is freed only once.  After freeing a chunk, set the pointer to NULL to ensure the pointer cannot be freed again.  In complicated error conditions, be sure that clean-up routines respect the state of allocation properly.  If the language is object oriented, ensure that object destructors delete each chunk of memory only once. '});

            flow.rule('Leftover Debug Code', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '2.2',
                        title:'Leftover Debug Code',
                        type:'Tampering',
                        status:'Open',
                        severity:'Medium',
                        description:'Debug code can create unintended entry points in a deployed web application. A common development practice is to add "back door" code specifically designed for debugging or testing purposes that is not intended to be shipped or deployed with the application.  When this sort of debug code is accidentally left in the application, the application is open to unintended modes of interaction.  These back-door entry points create security risks because they are not considered during design or testing and fall outside of the expected operating conditions of the application. '});

            flow.rule('Memory Leak', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '2.3',
                        title:'Memory Leak',
                        type:'Denial of service',
                        status:'Open',
                        severity:'High',
                        description:'A memory leak is an unintentional form of memory consumption whereby the developer fails to free an allocated block of memory when no longer needed.  The consequences of such an issue depend on the application itself.  Consider the following general three cases:Short Lived User-land Application: Little if any noticeable effect.  Modern operating system recollects lost memory after program termination. Long Lived User-land Application: Potentially dangerous.  These applications continue to waste memory over time, eventually consuming all RAM resources.  Leads to abnormal system behavior. Kernel-land Process: Memory leaks in the kernel level lead to serious system stability issues.  Kernel memory is very limited compared to user land memory and should be handled cautiously. Memory is allocated but never freed.  Memory leaks have two common and sometimes overlapping causes:-Error conditions and other exceptional circumstances. -Confusion over which part of the program is responsible for freeing the memory. Most memory leaks result in general software reliability problems, but if an attacker can intentionally trigger a memory leak, the attacker might be able to launch a denial of service attack (by crashing the program) or take advantage of other unexpected program behavior resulting from a low memory condition. '});

            flow.rule('Null Dereference', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '2.4',
                        title:'Null Dereference',
                        type:'Denial of service',
                        status:'Open',
                        severity:'Medium',
                        description:'The program can potentially dereference a null pointer, thereby raising a NullPointerException.  Null pointer errors are usually the result of one or more programmer assumptions being violated.  Most null pointer issues result in general software reliability problems, but if an attacker can intentionally trigger a null pointer dereference, the attacker might be able to use the resulting exception to bypass security logic or to cause the application to reveal debugging information that will be valuable in planning subsequent attacks. A null-pointer dereference takes place when a pointer with a value of NULL is used as though it pointed to a valid memory area. Null-pointer dereferences, while common, can generally be found and corrected in a simple way.  They will always result in the crash of the process, unless exception handling (on some platforms) is invoked, and even then, little can be done to salvage the process. '});

            flow.rule('Logging Practices', [[Element, 'el','el.element.attributes.type == "tm.Store" && isTrue(el.element.isALog)'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '2.5',
                        title:'Logging Practices',
                        type:'Denial of service',
                        status:'Open',
                        severity:'Low',
                        description:'Declare Logger Object as Static and Final:It is good programming practice to share a single logger object between all of the instances of a particular class and to use the same logger for the duration of the program. Don’t Use Multiple Loggers:It is a poor logging practice to use multiple loggers rather than logging levels in a single class. Good logging practice dictates the use of a single logger that supports different logging levels for each class. Don’t Use System Output Stream:Using System. out or System. err rather than a dedicated logging facility makes it difficult to monitor the behavior of the program.  It can also cause log messages accidentally returned to the end users, revealing internal information to attackers.  While most programmers go on to learn many nuances and subtleties about Java, a surprising number hang on to this first lesson and never give up on writing messages to standard output using System. out. println(). The problem is that writing directly to standard output or standard error is often used as an unstructured form of logging.  Structured logging facilities provide features like logging levels, uniform formatting, a logger identifier, timestamps, and, perhaps most critically, the ability to direct the log messages to the right place.  When the use of system output streams is jumbled together with the code that uses loggers properly, the result is often a well-kept log that is missing critical information.  In addition, using system output streams can also cause log messages accidentally returned to end users, revealing application internal information to attackers. Developers widely accept the need for structured logging, but many continue to use system output streams in their "pre-production" development.  If the code you are reviewing is past the initial phases of development, use of System. out or System. err may indicate an oversight in the move to a structured logging system. '});

            flow.rule('Portability', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '2.6',
                        title:'Portability',
                        type:'Tampering',
                        status:'Open',
                        severity:'Low',
                        description:'Functions with inconsistent implementations across operating systems and operating system versions cause portability problems. The behavior of functions in this category varies by operating system, and at times, even by operating system version.  Implementation differences can include:-Slight differences in the way parameters are interpreted, leading to inconsistent results. -Some implementations of the function carry significant security risks. -The function might not be defined on all platforms. '});

            flow.rule('Undefined Behavior', [[Element, 'el','el.element.attributes.type == "tm.Process"|| el.element.attributes.type == "tm.Store"'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '2.7',
                        title:'Undefined Behavior',
                        type:'Tampering',
                        status:'Open',
                        severity:'Low',
                        description:'The behavior of this function is undefined unless its control parameter is set to a specific value. The Linux Standard Base Specification 2. 0. 1 for libc places constraints on the arguments to some internal functions . '});

            flow.rule('Unreleased Resource', [[Element, 'el','el.element.attributes.type == "tm.Process"|| el.element.attributes.type == "tm.Store"'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '2.8',
                        title:'Unreleased Resource',
                        type:'Denial of service',
                        status:'Open',
                        severity:'Medium',
                        description:'Most unreleased resource issues result in general software reliability problems, but if an attacker can intentionally trigger a resource leak, the attacker might be able to launch a denial of service attack by depleting the resource pool. Resource leaks have at least two common causes:-Error conditions and other exceptional circumstances. -Confusion over which part of the program is responsible for releasing the resource. '});

            flow.rule('Use of Obsolete Methods', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '2.9',
                        title:'Use of Obsolete Methods',
                        type:'Denial of service',
                        status:'Open',
                        severity:'Medium',
                        description:'The use of deprecated or obsolete functions may indicate neglected code. As programming languages evolve, functions occasionally become obsolete due to:-Advances in the language-Improved understanding of how operations should be performed effectively and securely-Changes in the conventions that govern certain operations-Functions that are removed are usually replaced by newer counterparts that perform the same task in some different and hopefully improved way. Refer to the documentation for this function in order to determine why it is deprecated or obsolete and to learn about alternative ways to achieve the same functionality.  The remainder of this text discusses general problems that stem from the use of deprecated or obsolete functions. Cryptography'});

            flow.rule('Sensitive Parameters in URI', [[Element, 'el','el.element.attributes.type == "tm.Process"'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '3.1',
                        title:'Sensitive Parameters in URI',
                        type:'Information Disclosure',
                        status:'Open',
                        severity:'Medium',
                        description:'Information exposure through query strings in URL is when sensitive data is passed to parameters in the URL.  This allows attackers to obtain sensitive data such as usernames, passwords, tokens (authX), database details, and any other potentially sensitive data.  Simply using HTTPS does not resolve this vulnerability. '});

            flow.rule('Insecure Randomness', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '3.2',
                        title:'Insecure Randomness',
                        type:'Information Disclosure',
                        status:'Open',
                        severity:'Medium',
                        description:'Standard pseudo-random number generators cannot withstand cryptographic attacks. Insecure randomness errors occur when a function that can produce predictable values is used as a source of randomness in security-sensitive context. Computers are deterministic machines, and as such are unable to produce true randomness.  Pseudo-Random Number Generators (PRNGs) approximate randomness algorithmically, starting with a seed from which subsequent values are calculated. There are two types of PRNGs: statistical and cryptographic.  Statistical PRNGs provide useful statistical properties, but their output is highly predictable and forms an easy to reproduce numeric stream that is unsuitable for use in cases where security depends on generated values being unpredictable.  Cryptographic PRNGs address this problem by generating output that is more difficult to predict.  For a value to be cryptographically secure, it must be impossible or highly improbable for an attacker to distinguish between it and a truly random value.  In general, if a PRNG algorithm is not advertised as being cryptographically secure, then it is probably a statistical PRNG and should not be used in security-sensitive contexts. '});

            flow.rule('Insufficient Entropy', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '3.3',
                        title:'Insufficient Entropy',
                        type:'Information Disclosure',
                        status:'Open',
                        severity:'Medium',
                        description:'When an undesirably low amount of entropy is available.  Pseudo Random Number Generators are susceptible to suffering from insufficient entropy when they are initialized, because entropy data may not be available to them yet. In many cases a PRNG uses a combination of the system clock and entropy to create seed data.  If insufficient entropy is available, an attacker can reduce the size magnitude of the seed value considerably.  Furthermore, by guessing values of the system clock, they can create a manageable set of possible PRNG outputs. '});

            flow.rule('Testing for SSL-TLS', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '3.4',
                        title:'Testing for SSL-TLS',
                        type:'Information Disclosure',
                        status:'Open',
                        severity:'Medium',
                        description:'Visit https://www. owasp. org/index. php/Testing_for_SSL-TLS_(OWASP-CM-001) for more information. '});

            flow.rule('Insufficient TLS Protection', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isFalse(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isFalse(el.element.isEncrypted))'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '3.5',
                        title:'Insufficient TLS Protection',
                        type:'Information Disclosure',
                        status:'Open',
                        severity:'High',
                        description:'Sensitive data must be protected when it is transmitted through the network.  Such data can include user credentials and credit cards.  As a rule of thumb, if data must be protected when it is stored, it must be protected also during transmission. HTTP is a clear-text protocol and it is normally secured via an SSL/TLS tunnel, resulting in HTTPS traffic.  The use of this protocol ensures not only confidentiality, but also authentication.  Servers are authenticated using digital certificates and it is also possible to use client certificate for mutual authentication. Even if high grade ciphers are today supported and normally used, some misconfiguration in the server can be used to force the use of a weak cipher - or at worst no encryption - permitting to an attacker to gain access to the supposed secure communication channel.  Other misconfiguration can be used for a Denial of Service attack. See: https://www. owasp. org/index. php/Testing_for_Weak_SSL/TLS_Ciphers,_Insufficient_Transport_Layer_Protection_(OTG-CRYPST-001)for more information'});

            flow.rule('Hard-coded Cryptographic Key', [[Element, 'el','(el.element.attributes.type == "tm.Flow" && isTrue(el.element.isEncrypted)) || (el.element.attributes.type == "tm.Store" && isTrue(el.element.isEncrypted))'],
                        [Threats, 'threats']
                    ], function (facts) {
                        facts.threats.collection.push({ ruleId: '3.6',
                        title:'Hard-coded Cryptographic Key',
                        type:'Information Disclosure',
                        status:'Open',
                        severity:'High',
                        description:'The use of a hard-coded cryptographic key tremendously increases the possibility that encrypted data may be recovered. Authentication: If hard-coded cryptographic keys are used, it is almost certain that malicious users will gain access through the account in question. '});



            flow.rule('Should encrypt on public network', [
                [Element, 'el', 'el.element.attributes.type == "tm.Flow" && isTrue(el.element.isPublicNetwork) && ( isFalse(el.element.isEncrypted) || isUndefined(el.element.isEncrypted) )'],
                [Threats, 'threats']
            ], function (facts) {
                facts.threats.collection.push({
                    ruleId: 'c1cae982-3e92-4bb2-b50b-ea51137fc3a7',
                    title: 'Use encryption',
                    type: 'Information disclosure',
                    status: 'Open',
                    severity: 'High',
                    description: 'Unencrypted data sent over a public network may be intercepted and read by an attacker.',
                    mitigation: 'Data sent over a public network should be encrypted either at the message or transport level.'
                });
            });
        });
    }
}

module.exports = threatengine;