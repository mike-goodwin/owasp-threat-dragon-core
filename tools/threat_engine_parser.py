#this script parses rule engine file and creates rules in json for for threatengine.js
import time
class rule:
    def __init__(self,title,logic,id,type,status,severity,description):
        self.title = title
        self.logic = logic
        self.id = id
        self.type = type
        self.status = status
        self.severity = severity
        self.description = description
        self.build_rule_string()

    def build_rule_string(self):
        rule_string = 'flow.rule(\''+self.title
        rule_string = rule_string +'\', [[Element, \'el\',\''
        rule_string = rule_string+self.logic
        rule_string = rule_string+'''\'],
            [Threats, 'threats']
        ], function (facts) {
            facts.threats.collection.push({ ruleId: \''''
        rule_string = rule_string+self.id+'\',\n' 
        rule_string = rule_string+'\t\t\ttitle:\''+self.title+'\',\n' 
        rule_string = rule_string+'\t\t\ttype:\''+self.type+'\',\n' 
        rule_string = rule_string+'\t\t\tstatus:\''+self.status+'\',\n'     
        rule_string = rule_string+'\t\t\tseverity:\''+self.severity+'\',\n'
        rule_string = rule_string+'\t\t\tdescription:\''+self.description.replace('.','. ').replace('\'','\\''')+'\'});});\n\n'
        self.rule_string = rule_string
    

    
def parse():

    all_rule_string = ''
    rules = 'Threat_Engine_Rules.txt'
    
    targets = []
    grab_off = ['1. ','2. ','3. ','4. ','5. ','6. ','7. ','8. ','9. ','10. ','11. ','12. ','13. ','14. ','15. ','16. ','17. ','18. ','19. ','20. ','To do...']
    key_words = ['Title','Rule Activation Logic','Rule ID','STRIDE Type','Status','Severity','Description']
    target_length = len(key_words)
    with open(rules,'r') as f:
        buffer = ''
        empty_buffer = ''
        count = 0
        grab = False

        for line in f:
            line = line.strip()
            line = line.lstrip()
            if line in key_words:
                
                grab = True
                if buffer != empty_buffer:
                    targets.append(buffer)
                    buffer = empty_buffer
            elif any(num in line for num in grab_off):
                grab = False
            elif grab:
                buffer = buffer+line
      
            if len(targets) == target_length:
                print('Rule Data Collection Complete')
                print(count)
                count = count + 1
                new_rule = rule(targets[0],targets[1],targets[2],targets[3],targets[4],targets[5],targets[6])
                all_rule_string = all_rule_string + new_rule.rule_string
                targets = []
    print(all_rule_string)
    with open('rules.json','w+') as f:
        f.write(all_rule_string)
                
                
                    
 

  
if __name__ == "__main__":
    parse()
