#this script parses rule engine file and creates rules in json for for threatengine.js
import time
class rule:
    def __init__(self,title,logic,id,type,status,severity,description, mitigation):
        self.title = title
        self.logic = logic
        self.id = id
        self.type = type
        self.status = status
        self.severity = severity
        self.description = description
        self.mitigation = mitigation.replace('/t','')
        i = len(grab_off) - 1
        while i >= 0:
            num = grab_off[i]
            self.mitigation, discardOne, discardTwo = self.mitigation.partition(num.replace(' ',''))
            i = i - 1
        self.build_rule_string()
    def build_rule_string(self):
        rule_string = 'flow.rule(\''+self.title+'\','
        if 'dropDownOptionsCheck' in self.logic:
            rule_string = rule_string +'{scope: {dropDownOptionsCheck: dropDownOptionsCheck}},'
        rule_string = rule_string +'[[Element, \'el\',\''
        rule_string = rule_string+self.logic
        rule_string = rule_string+'''\'],
            [Threats, 'threats']
        ], function (facts) {
            facts.threats.collection.push({ ruleId: \''''
        rule_string = rule_string+self.id+'\',\n' 
        rule_string = rule_string+'title:\''+self.title+'\',\n' 
        rule_string = rule_string+'type:\''+self.type+'\',\n' 
        rule_string = rule_string+'status:\''+self.status+'\',\n'     
        rule_string = rule_string+'severity:\''+self.severity+'\',\n'
        rule_string = rule_string+'description:\''+self.description+'\',\n'
        rule_string = rule_string+'mitigation:\''+self.mitigation+'\',\n'
        reference_string = self.format_reference()
        rule_string = rule_string+'references:['+reference_string+']});});\n\n'
        self.rule_string = rule_string
    def format_reference(self):
        ref = ''
        n = 0
        for key in references.keys():
            if key in self.description or key in self.mitigation:
                name = references[key][0].lstrip().replace('\'','\\\'')
                link = references[key][1].lstrip()
                if n == 0:
                    ref = ref+'{name:\''+name+'\', link:\''+link+'\'}'
                else:
                    ref = ref+',{name:\''+name+'\', link:\''+link+'\'}'
                n = n + 1
        if n!=0:
            ref = ref+''
        return ref
def get_references(reference_file):
    reference_holder = {}
    with open(reference_file,'r') as f:
        for line in f:
            if '[' in line:
                line = line.strip()
                line = line.split(',')
                number = line[0]
                name = line[1]
                link = line[2]
                reference_holder[number.replace(' ','')] = [name,link]
                
    return reference_holder
def parse():
    global references
    global grab_off
    global to_remove
    all_rule_string = ''
    rules = 'Threat_Engine_Rules.txt'
    reference_file = 'References.txt'
    references = get_references(reference_file)
    targets = []
    grab_off = ['1. ','2. ','3. ','4. ','5. ','6. ','7. ','8. ','9. ','10. ','11. ','12. ','13. ','14. ','15. ','16. ','17. ','18. ','19. ','20. ','To do...']
    key_words = ['Title','Rule Activation Logic','Rule ID','STRIDE Type','Status','Severity','Description', 'Mitigation(s)']
    content_sections = ['Description', 'Mitigation(s)']
    target_length = len(key_words)
    with open(rules,'r') as f:
        buffer = ''
        empty_buffer = ''
        count = 0
        grab = False
        grabLogic = False
        to_remove = []
        for line in f:
            holder = line
            if line[0] == '1' and line[1] =='.':
                to_remove.append(prev_line)
            if line[len(line)-2] == ' ':
                line = line.strip()
                line = line + ' '
            else:
                line = line.strip()
            line = line.lstrip()
            if line in key_words:
                if line in 'Rule Activation Logic':
                    grabLogic = True
                
                grab = True
                if buffer != empty_buffer:
                    targets.append(buffer)
                    buffer = empty_buffer
            elif any(num in line for num in grab_off):
                grab = False
                grabLogic = False
            elif grab:
                if grabLogic:
                    buffer = buffer+line
                else:
                    buffer = buffer+line+' '
            if len(targets) == target_length:
                count = count + 1
                new_rule = rule(targets[0],targets[1],targets[2],targets[3],targets[4],targets[5],targets[6], targets[7])
                all_rule_string = all_rule_string + new_rule.rule_string
                targets = []
            prev_line = holder.strip()
    for text in to_remove:
            all_rule_string = all_rule_string.replace(text,'')
    with open('rules.json','w+') as f:
        f.write(all_rule_string.replace('&&i','&& i'))
                
                
                    
 

  
if __name__ == "__main__":
    parse()