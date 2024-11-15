import re
from lxml import etree
from collections import defaultdict

group_number_regex = re.compile(r'^xccdf_org\..+\.benchmarks_group_((\d+\.?)+)_')
rule_number_regex = re.compile(r'^xccdf_org\..+\.benchmarks_rule_((\d+\.)+\d+)_')

class XccdfOvalParser:
    def __init__(self):
        self.rule_count = 0
        self.rule_list = []
        self.namespaces = {
            'xccdf': 'http://checklists.nist.gov/xccdf/1.1',
            'oval-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5',
            'win': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#windows',
            'ind-def': 'http://oval.mitre.org/XMLSchema/oval-definitions-5#independent'
        }
        self.all_values = {}

    def get_local_name(self, tag):
        return tag.split('}')[-1] if isinstance(tag, str) else getattr(tag, 'localname', str(tag))

    def extract_element_info(self, element):
        info = {f"@{self.get_local_name(attr)}": value for attr, value in element.attrib.items()}
        for child in element:
            child_name = self.get_local_name(child.tag)
            child_info = self.extract_element_info(child)
            if child.text and child.text.strip():
                child_info['#text'] = child.text.strip()
            if child_name in info:
                if not isinstance(info[child_name], list):
                    info[child_name] = [info[child_name]]
                info[child_name].append(child_info)
            else:
                info[child_name] = child_info
        return info

    def parse_oval(self, oval_path):
        oval_tree = etree.parse(oval_path)
        oval_root = oval_tree.getroot()

        test_map = self.process_elements(oval_root.findall('.//oval-def:tests/*', namespaces=self.namespaces), self.process_test)
        object_map = self.process_elements(oval_root.findall('.//oval-def:objects/*', namespaces=self.namespaces), self.process_object)
        state_map = self.process_elements(oval_root.findall('.//oval-def:states/*', namespaces=self.namespaces), self.process_state)
        variable_map = self.process_elements(oval_root.findall('.//oval-def:variables/*', namespaces=self.namespaces), self.process_variable)

        return self.process_definitions(oval_root.findall('.//oval-def:definition', namespaces=self.namespaces), test_map, object_map, state_map, variable_map)

    def process_elements(self, elements, process_func):
        return {elem.get('id'): process_func(elem) for elem in elements}

    def process_test(self, test):
        object_elem = test.find('.//*[@object_ref]')
        state_elem = test.find('.//*[@state_ref]')
        return {
            'check': test.get('check'),
            'check_existence': test.get('check_existence'),
            'comment': test.get('comment'),
            'id': test.get('id'),
            'version': test.get('version'),
            'type': self.get_local_name(test.tag),
            'object': object_elem.get('object_ref') if object_elem is not None else None,
            'state': state_elem.get('state_ref') if state_elem is not None else None,
            'elements': self.extract_element_info(test)
        }

    def process_object(self, obj):
        return {
            'type': self.get_local_name(obj.tag),
            'comment': obj.get('comment', ''),
            'version': obj.get('version'),
            'elements': self.extract_element_info(obj)
        }

    def process_state(self, state):
        return {
            'type': self.get_local_name(state.tag),
            'elements': self.extract_element_info(state)
        }

    def process_variable(self, variable):
        return {
            'type': self.get_local_name(variable.tag),
            'comment': variable.get('comment', ''),
            'version': variable.get('version'),
            'datatype': variable.get('datatype'),
            'elements': self.extract_element_info(variable)
        }

    def process_definitions(self, definitions, test_map, object_map, state_map, variable_map):
        oval_to_xccdf_map = {}
        for definition in definitions:
            oval_id = definition.get('id')
            xccdf_ref = definition.find('.//oval-def:reference', namespaces=self.namespaces)
            if xccdf_ref is not None:
                xccdf_id = xccdf_ref.get('ref_id')
                title = definition.find('.//oval-def:title', namespaces=self.namespaces)
                description = definition.find('.//oval-def:description', namespaces=self.namespaces)
                criteria = definition.find('.//oval-def:criteria', namespaces=self.namespaces)
                
                oval_to_xccdf_map[oval_id] = {
                    'xccdf_id': xccdf_id,
                    'xccdf_family': self.get_affected_info(definition.find('.//oval-def:affected', namespaces=self.namespaces)),
                    'title': title.text if title is not None else "No title",
                    'description': description.text if description is not None else "No description",
                    'associated_tests': self.process_criteria(criteria, test_map, object_map, state_map, variable_map)
                }
        return oval_to_xccdf_map

    def get_affected_info(self, xccdf_aff):
        if xccdf_aff is not None:
            family = xccdf_aff.get('family', 'Not specified')
            product = xccdf_aff.find('.//oval-def:product', namespaces=self.namespaces)
            return family, product.text if product is not None else 'Not specified'
        return 'Not specified', 'Not specified'

    def process_criteria(self, criteria, test_map, object_map, state_map, variable_map):
        if criteria is None:
            return [], 'Not specified'
        
        associated_tests = []
        for criterion in criteria.findall('.//oval-def:criterion', namespaces=self.namespaces):
            test_ref = criterion.get('test_ref')
            if test_ref in test_map:
                test_info = test_map[test_ref]
                object_ref = test_info['object']
                state_ref = test_info['state']
                object_info = object_map.get(object_ref, {})
                state_info = state_map.get(state_ref, {})
                
                associated_tests.append({
                    'test_id': test_ref,
                    'test_type': test_info['type'],
                    'test_comment': test_info['comment'],
                    'test_check': test_info['check'],
                    'test_check_existence': test_info['check_existence'],
                    'test_elements': test_info['elements'],
                    'object_ref': object_ref,
                    'object_type': object_info.get('type'),
                    'object_comment': object_info.get('comment', ''),
                    'object_version': object_info.get('version'),
                    'object_elements': object_info.get('elements', {}),
                    'object_variables': self.find_variable_refs(object_info.get('elements', {}), variable_map),
                    'state_ref': state_ref,
                    'state_type': state_info.get('type'),
                    'state_elements': state_info.get('elements', {}),
                    'state_variables': self.find_variable_refs(state_info.get('elements', {}), variable_map)
                })
        return associated_tests, criteria.get('operator', 'Not specified')

    def find_variable_refs(self, elements, variable_map):
        variable_refs = {}
        for key, value in elements.items():
            if isinstance(value, str):
                if value.startswith('$') or (value.startswith('oval:') and value in variable_map):
                    variable_refs[key] = {
                        'var_ref': value,
                        'var_type': variable_map.get(value, {}).get('type'),
                        'var_elements': variable_map.get(value, {}).get('elements', {})
                    }
            elif isinstance(value, dict):
                nested_vars = self.find_variable_refs(value, variable_map)
                if nested_vars:
                    variable_refs[key] = nested_vars
            elif isinstance(value, list):
                variable_refs[key] = []
                for item in value:
                    if isinstance(item, dict):
                        nested_vars = self.find_variable_refs(item, variable_map)
                        if nested_vars:
                            variable_refs[key].append(nested_vars)
                    elif isinstance(item, str) and (item.startswith('$') or (item.startswith('oval:') and item in variable_map)):
                        variable_refs[key].append({
                            'var_ref': item,
                            'var_type': variable_map.get(item, {}).get('type'),
                            'var_elements': variable_map.get(item, {}).get('elements', {})
                        })
        return variable_refs

    def parse_xccdf(self, input_path):
        parser = etree.XMLParser(remove_blank_text=True, resolve_entities=False, ns_clean=True)
        self.tree = etree.parse(input_path, parser=parser)
        self.benchmark_el = self.tree.getroot()
        self.get_root_namespace()
        self.process_all_values()

        benchmark_info = self.extract_benchmark_info()
        profile_info = self.extract_profile_info()

        self.profiles = self.find_profiles()
        self.groups = self.find_groups()

        return {
            'benchmark': benchmark_info,
            'profiles': profile_info,
            'groups': self.groups,
            'profile_mapping': self.profile_mapping,
            'profile_result': self.profile_result,
            'rule_list': list(self.rule_list),
            'profile_count': len(self.profiles),
            'group_count': len(self.groups),
            'rule_count': self.rule_count,
            'namespaces': self.namespaces,
        }

    def extract_benchmark_info(self):
        return {
            'id': self.benchmark_el.get('id'),
            'title': self.get_element_text(self.benchmark_el, 'xccdf:title'),
            'description': self.get_element_text(self.benchmark_el, 'xccdf:description'),
            'version': self.get_element_text(self.benchmark_el, 'xccdf:version'),
            'status': self.get_element_text(self.benchmark_el, 'xccdf:status'),
        }

    def extract_profile_info(self):
        self.profile_mapping = {}
        self.profile_result = defaultdict(lambda: defaultdict(set))
        profile_info = []

        for profile in self.benchmark_el.findall('.//xccdf:Profile', self.namespaces):
            profile_id = profile.get('id')
            title = self.get_element_text(profile, 'xccdf:title')
            description = self.get_element_text(profile, 'xccdf:description')
            
            title_text = title.lower() if title else ""
            product_type = self.determine_product_type(title_text)
            level = self.determine_level(title_text)
            
            self.profile_mapping[profile_id] = (product_type, level)
            
            selected_rules = []
            for selection in profile.findall('.//xccdf:select', self.namespaces):
                idref = selection.get('idref')
                selected = selection.get('selected')
                if idref:
                    self.profile_result[product_type][level].add(idref)
                    selected_rules.append({'idref': idref, 'selected': selected})
            
            profile_info.append({
                'id': profile_id,
                'title': title,
                'description': description,
                'product_type': product_type,
                'level': level,
                'selected_rules': selected_rules
            })

        return profile_info

    def get_element_text(self, element, xpath):
        el = element.find(xpath, namespaces=self.namespaces)
        return ' '.join(el.itertext()).strip() if el is not None else None

    def get_root_namespace(self):
        if self.benchmark_el.tag[0] == '{':
            uri, tag = self.benchmark_el.tag[1:].split('}')
            self.namespaces['xccdf'] = uri

    def determine_product_type(self, title):
        if 'domain controller' in title:
            return 'domain_controller'
        elif 'server' in title:
            return 'server'
        elif 'workstation' in title:
            return 'workstation'
        else:
            return 'default'

    def determine_level(self, title):
        if 'level 1' in title or 'l1' in title:
            return 'level1'
        elif 'level 2' in title or 'l2' in title:
            return 'level2'
        elif 'next generation' in title:
            return 'nextgen'
        elif 'bitlocker' in title:
            return 'bitlocker'
        else:
            return 'other'

    def find_profiles(self):
        profile_els = self.tree.xpath(f'./{self.make_el_name("Profile")}', namespaces=self.namespaces)
        return [{
            'id': profile_el.get('id'),
            'title': profile_el.xpath(f'./{self.make_el_name("title")}', namespaces=self.namespaces)[0].text if profile_el.xpath(f'./{self.make_el_name("title")}', namespaces=self.namespaces) else "",
            'selections': [{
                'idref': select_el.get('idref'),
                'selected': select_el.get('selected')
            } for select_el in profile_el.xpath(f'.//{self.make_el_name("select")}', namespaces=self.namespaces)]
        } for profile_el in profile_els]

    def find_groups(self):
        groups = []
        group_els = self.tree.xpath("//*[local-name()='Group']")
        for group_el in group_els:
            group = self.process_group(group_el)
            groups.append(group)
        return groups

    def process_group(self, group_el):
        group = {
            'id': group_el.get('id'),
            'title': self.get_element_text(group_el, 'xccdf:title'),
            'description': self.get_element_text(group_el, 'xccdf:description'),
            'rules': [],
            'subgroups': []
        }

        match = group_number_regex.search(group['id'])
        if match:
            group['number'] = match[1]

        # Process rules
        rule_els = group_el.xpath(f'./{self.make_el_name("Rule")}', namespaces=self.namespaces)
        for rule_el in rule_els:
            rule = self.process_rule(rule_el)
            group['rules'].append(rule)

        # Process subgroups
        subgroup_els = group_el.xpath(f'./{self.make_el_name("Group")}', namespaces=self.namespaces)
        for subgroup_el in subgroup_els:
            subgroup = self.process_group(subgroup_el)
            group['subgroups'].append(subgroup)

        return group

    def process_complex_check(self, rule_el):
        complex_check_el = rule_el.find('.//xccdf:complex-check', namespaces=self.namespaces)
        if complex_check_el is None:
            return None

        complex_check = {
            'operator': complex_check_el.get('operator'),
            'checks': []
        }

        check_els = complex_check_el.findall('.//xccdf:check', namespaces=self.namespaces)
        for check_el in check_els:
            check = self.process_check(check_el)
            if check:
                complex_check['checks'].append(check)

        return complex_check

    def process_check(self, check_el):
        if check_el is None:
            return None

        check = {
            'system': check_el.get('system'),
            'content_ref': {},
            'check_export': []
        }

        content_ref_el = check_el.find('.//xccdf:check-content-ref', namespaces=self.namespaces)
        if content_ref_el is not None:
            check['content_ref'] = {
                'href': content_ref_el.get('href'),
                'name': content_ref_el.get('name')
            }

        check_export_els = check_el.findall('.//xccdf:check-export', namespaces=self.namespaces)
        for export_el in check_export_els:
            check['check_export'].append({
                'export_name': export_el.get('export-name'),
                'value_id': export_el.get('value-id')
            })

        return check

    def process_rule(self, rule_el):
        rule = {
            'id': rule_el.get('id'),
            'title': self.get_element_text(rule_el, 'xccdf:title'),
            'description': self.get_element_text(rule_el, 'xccdf:description'),
            'rationale': self.get_element_text(rule_el, 'xccdf:rationale'),
            'impact': rule_el.get('weight'),
            'severity': rule_el.get('severity'),
            'idents': [],
            'fixtext': self.get_element_text(rule_el, 'xccdf:fixtext'),
            'complex_check': self.process_complex_check(rule_el),
            'values': {}
        }

        match = rule_number_regex.search(rule['id'])
        if match:
            rule['number'] = match[1]

        ident_els = rule_el.xpath(f'./{self.make_el_name("ident")}', namespaces=self.namespaces)
        for ident_el in ident_els:
            rule['idents'].append({
                'system': ident_el.get('system'),
                'text': ident_el.text
            })

        # Process values
        if rule['complex_check']:
            for check in rule['complex_check']['checks']:
                for export in check.get('check_export', []):
                    value_id = export['value_id']
                    if value_id in self.all_values:
                        rule['values'][value_id] = self.all_values[value_id]

        parsed_rule = re.search('(\d+(\.\d+)+)_(\D.*)', rule['id'])
        if parsed_rule:
            rule_text = f"{parsed_rule.group(1)} - {parsed_rule.group(3).replace('_',' ')}"
        else:
            rule_text = f"{rule['id']} - {rule['title']}"

        # Check if the rule is already in the set before adding it
        if rule_text not in self.rule_list:
            self.rule_list.append(rule_text)
            self.rule_count += 1

        return rule

    def process_all_values(self):
        self.all_values = {}
        value_els = self.tree.xpath('//xccdf:Value', namespaces=self.namespaces)
        for value_el in value_els:
            value_id = value_el.get('id')
            value = {
                'id': value_id,
                'type': value_el.get('type'),
                'operator': value_el.get('operator'),
                'title': self.get_element_text(value_el, 'xccdf:title'),
                'description': self.get_element_text(value_el, 'xccdf:description'),
                'value': self.get_element_text(value_el, 'xccdf:value')
            }
            self.all_values[value_id] = value

    def make_el_name(self, name):
        return f'xccdf:{name}' if self.namespaces else name