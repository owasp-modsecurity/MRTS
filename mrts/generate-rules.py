#!/usr/bin/env python3

import argparse
import sys
import yaml
import os
import os.path
import string
import re
import copy
from ast import literal_eval
import urllib.parse

NAME = "MRTS"
VERSION = "0.1"


class RuleGenerator(object):
    def __init__(self, flist, expdir, testdir):
        # set initial values
        self.version          = "%s/%s" % (NAME, VERSION)
        self.baseid           = 100000
        self.currid           = self.baseid
        self.templates        = []
        self.templates_dict   = {}
        self.default_operator  = "@rx"
        self.confdata         = {
            'target'       : None,
            'rulefile'     : None,
            'testfile'     : None,
            'templates'    : [],
            'colkey'       : [],
            'operator'     : self.default_operator,
            'oparg'        : "attack",
            'phase'        : [1,2,3,4],
            'actions'      : [],
            'directives'   : [],
            'constants'    : {},
            'generation'   : {},
            'phase_methods': {}
        }
        self.default_test_phase_methods = {
            1: "get",
            2: "post",
            3: "post",
            4: "post",
            5: "post"
        }

        self.default_constants = {}

        self.current_confdata = {}
        self.current_testdata = {}

        self.indent           = "    "
        self.indentdepth      = 0
        self.expdir           = expdir
        self.testdir          = testdir
        self.content          = ""
        self.testcontent      = {}

        self.re_tplvars  = re.compile(r"""\$\{[^ \n\t$,'"]*\}\$""")
        self.re_constants = re.compile(r"""~\{([^ \n\t$,'"]*)\}~""")

        self.testdict         = {
            'header': {
                'meta': {
                    'author': 'MRTS generate-rules.py',
                    'enabled': True,
                    'name': '',
                    'description': 'Desc'
                },
                'tests': []
            },
            'item': {
                'test_title': '',
                'ruleid': 0,
                'test_id': 0,
                'desc': '',
                'stages': [
                    {
                        'description': '',
                        'input': {
                            'dest_addr': '127.0.0.1',
                            'port': 80,
                            'protocol': 'http',
                            'method': '',
                            'headers': {
                                'User-Agent': 'OWASP MRTS test agent',
                                'Host': 'localhost',
                                'Accept': 'text/xml,application/xml,application/xhtml+xml,text/html;q=0.9,text/plain;q=0.8,image/png,*/*;q=0.5'
                            },
                            'uri': '/',
                            'version': 'HTTP/1.1'
                        },
                        'output': {
                            'log': {
                                'expect_ids': []
                            }
                        }
                    }
                ]
            }
        }

        # walk through the files and process them
        for f in flist:
            try:
                with open(f, 'r') as fp:
                    print("Processing file: %s" % (f))
                    t = yaml.safe_load(fp)
                    self.current_confdata = copy.deepcopy(self.confdata)
                    self.current_confdata['phase_methods'] = copy.deepcopy(self.default_test_phase_methods)
                    self.current_testdata = {}
                    self.parseconf(t)
                    self.content = ""
                    self.testcontent = {}
            except Exception as e:
                print("Can't open file: %s" % (f))
                print(", ".join(e.args))
                sys.exit(1)

    def parseconf(self, c):
        """parsing a configuration file"""
        # Before anything, load and replace constants for the current file.
        if re.search(self.re_constants, str(c)) is not None:
            c = self.parseconstants(c)

        # if there is a 'global' section, fill the possible global vars
        if 'global' in c:
            for k in c['global']:
                if hasattr(self, k):
                    setattr(self, k, c['global'][k])

            if len(self.templates) > 0:
                for t in self.templates:
                    self.templates_dict[t['name']] = t['template']

        # if there is a target, rulefile or testfile keyword, set the correct variable
        for k in list(self.confdata.keys()):
            if k in c and c[k] is not None:
                self.current_confdata[k] = c[k]

        # if config contains 'testdata' key, fill the current structure with it
        if 'testdata' in c:
            self.current_testdata = copy.deepcopy(c['testdata'])

        # if any template is applied, run with that, else exit
        if len(self.current_confdata['templates']) > 0:
            for t in self.current_confdata['templates']:
                if t in self.templates_dict:
                    tpl = self.templates_dict[t]
                    self.genrulefromtemplate(tpl, self.current_confdata)
                else:
                    print("No such template: %s" % (t))
                    print("Avaliable templates: %s" % (", ".join(list(self.templates_dict.keys()))))
                    sys.exit(1)

        # if there is an 'object' section, process them one-by-one
        if 'objects' in c:
            for o in c['objects']:
                self.genobject(o)

        # finally, write the generated config file
        if self.current_confdata['rulefile'] is not None:
            self.writeconf(self.content)
        else:
            pass

    def parseconstants(self, c):
        """Load and replace any used constants in current configuration"""
        # per-file local
        if 'constants' in c:
            self.current_confdata['constants'] = c['constants']
        # cross-file global
        if 'global' in c:
            if 'default_constants' in c['global']:
                self.default_constants = c['global']['default_constants']
            else:  # if no global constants, reset values defined under previous 'global' field
                self.default_constants = {}
        return self.swap_constants(c)

    def swap_constants(self, c):
        if isinstance(c, dict):
            for key, val in c.items():
                c[key] = self.swap_constants(val)
        if isinstance(c, list):
            for i in range(len(c)):
                c[i] = self.swap_constants(c[i])
        if isinstance(c, str):
            matches = re.findall(self.re_constants, c)
            for match in matches:
                if match in self.current_confdata['constants']:
                    og_type = type(self.current_confdata['constants'][match])
                    c = c.replace(f"~{{{match}}}~", str(self.current_confdata['constants'][match]))
                    if og_type in (list, dict):
                        c = literal_eval(c)
                    else:
                        c = og_type(c)
                elif match in self.default_constants:
                    og_type = type(self.default_constants[match])
                    c = c.replace(f"~{{{match}}}~", str(self.default_constants[match]))
                    if og_type in (list, dict):
                        c = literal_eval(c)
                    else:
                        c = og_type(c)
        return c

    def genrulefromtemplate(self, tpl, current_confdata):
        """
            generate a rule from data based on the template
            tpl: applied template
            current_confdata: content of processing file
        """

        # get the template vars; 'colkey' is not a tpl variable, but
        # needs for TARGET:colkey variables
        tplvars = [t.replace("${", "").replace("}$", "").lower() for t in self.re_tplvars.findall(tpl)]
        tplvars.append('colkey')
        tplvars.append('generation')

        # build a dict for template vars
        tpldict = {}
        for t in tplvars:
            if t in current_confdata:
                tpldict[t] = current_confdata[t]
            elif hasattr(self, t):
                tpldict[t] = getattr(self, t)

        # place before/after each directives to separate templates
        before_defined = 'before' in tpldict['generation']
        after_defined = 'after' in tpldict['generation']
        before_each_defined = 'before_each' in tpldict['generation']
        after_each_defined = 'after_each' in tpldict['generation']
        if before_defined:
            before_tpl = RuleGeneratorTemplate(tpldict['generation']['before'])
        if after_defined:
            after_tpl = RuleGeneratorTemplate(tpldict['generation']['after'])
        if before_each_defined:
            before_each_tpl = RuleGeneratorTemplate(tpldict['generation']['before_each'])
        if after_each_defined:
            after_each_tpl = RuleGeneratorTemplate(tpldict['generation']['after_each'])

        ruletpl = RuleGeneratorTemplate(tpl)

        # current rule id
        tpldict['currid'] = self.currid

        # optional actions macro
        actions_defined = 'actions' in tpldict
        if not actions_defined:
            tpldict['actions'] = [None]  # dummy but iterable value

        # optional directives macro
        directives_defined = 'directives' in tpldict
        if not directives_defined:
            tpldict['directives'] = [None]  # dummy but iterable

        # add before all directives with CURRID substitution
        if before_defined:
            before = before_tpl.ruleid_substitute(increment_id_after_sub=True, **{'CURRID': tpldict['currid']}) + "\n"
            self.content += before
            self.currid = before_tpl.get_last_id()
            tpldict['CURRID'] = self.currid

        # iterate loops through possible combinations of arguments
        # mandatory arguments are 'colkey', 'operator', 'oparg' and 'phase'
        # optional arguments are 'actions', 'directives'
        # this 6 loop produces the combinations
        for directive in tpldict['directives']:
            for action in tpldict['actions']:
                for c in tpldict['colkey']:
                    for op in tpldict['operator']:
                        for oparg in tpldict['oparg']:
                            for phase in tpldict['phase']:
                                tdict = copy.deepcopy(tpldict)
                                if len(c) > 1:
                                    tdict['target'] = "|".join(["%s:%s" % (tpldict['target'], ck) for ck in c])
                                elif len(c) == 1 and c[0] != '':
                                    tdict['target'] = "%s:%s" % (tpldict['target'], c[0])
                                else:
                                    tdict['target'] = "%s" % (tpldict['target'])
                                tdict['operator'] = op
                                tdict['oparg'] = oparg
                                tdict['phase'] = phase
                                if actions_defined:
                                    tdict['actions'] = self.parseactions(action['action'])
                                if directives_defined:
                                    tdict['directives'] = self.parsedirectives(directive['directive'])

                                td = {}
                                for k in tdict:
                                    td[k.upper()] = tdict[k]
                                td['CURRID'] = self.currid

                                if before_each_defined:
                                    before_each = before_each_tpl.ruleid_substitute(increment_id_after_sub=True, **td) + "\n"
                                    self.content += before_each
                                    self.currid = before_each_tpl.get_last_id()
                                    td['CURRID'] = self.currid

                                rule = ruletpl.substitute(**td) + "\n"
                                if directives_defined:
                                    dirtpl = RuleGeneratorTemplate(rule)
                                    rule = dirtpl.ruleid_substitute(**td)
                                    last_id = dirtpl.get_last_id()

                                self.content += rule

                                if after_each_defined:
                                    after_each = after_each_tpl.ruleid_substitute(**td) + "\n"
                                    self.content += after_each
                                    last_id = after_each_tpl.get_last_id()


                                # create a test if testfile was given
                                if self.current_confdata['testfile'] is not None:
                                    testcnt = 1
                                    for ck in c:
                                        if 'targets' in self.current_testdata:
                                            for test in self.current_testdata['targets']:
                                                if ck == '' or test['target'] == ck:
                                                    # first colkey which matches in the list
                                                    # create a test object
                                                    if self.testcontent == {}:
                                                        self.testcontent = copy.deepcopy(self.testdict['header'])
                                                        self.testcontent['meta']['name'] = self.current_confdata['testfile']
                                                    item = copy.deepcopy(self.testdict['item'])
                                                    item['test_title'] = "%d-%d" % (self.currid, testcnt)
                                                    item['ruleid'] = self.currid
                                                    item['test_id'] = testcnt
                                                    item['desc'] = "Test case for rule %d, #%d" % (self.currid, testcnt)
                                                    item['stages'][0]['description'] = "Send request"
                                                    item['stages'][0]['input']['method'] = self.current_confdata['phase_methods'][phase].upper()
                                                    method = self.current_testdata['phase_methods'][phase].lower()
                                                    data = test['test']['data']
                                                    if method == "post":
                                                        if isinstance(data, dict):
                                                            encoded_data = urllib.parse.urlencode(data)
                                                            item['stages'][0]['input']['data'] = encoded_data
                                                        elif isinstance(data, str):
                                                            item['stages'][0]['input']['data'] = data
                                                        item['stages'][0]['input']['uri'] = "/post"
                                                    elif method == "get":
                                                        if isinstance(data, dict):
                                                            query = urllib.parse.urlencode(data)
                                                            item['stages'][0]['input']['uri'] = "/?" + query
                                                    # add headers if there are
                                                    if 'input' in test['test']:
                                                        if 'headers' in test['test']['input']:
                                                            for h in test['test']['input']['headers']:
                                                                item['stages'][0]['input']['headers'][h['name']] = h['value']
                                                        if 'encoded_request' in test['test']['input']:
                                                            item['stages'][0]['input']['encoded_request'] = test['test']['input']['encoded_request']
                                                        if 'uri' in test['test']['input']:
                                                            item['stages'][0]['input']['uri'] = test['test']['input']['uri']
                                                    # overwrite default output field
                                                    if 'output' in test['test']:
                                                        item['stages'][0]['output'] = test['test']['output']
                                                        # if [no_]expect_ids is in rewrite, append the current rule id
                                                        if 'log' in item['stages'][0]['output']:
                                                            if 'expect_ids' in item['stages'][0]['output']['log']:
                                                                item['stages'][0]['output']['log']['expect_ids'] = [self.currid]
                                                            if 'no_expect_ids' in item['stages'][0]['output']['log']:
                                                                item['stages'][0]['output']['log']['no_expect_ids'] = [self.currid]
                                                    else:
                                                        item['stages'][0]['output']['log']['expect_ids'].append(self.currid)

                                                    self.testcontent['tests'].append(item)
                                                    testcnt += 1
                                    # if no testdata
                                    if self.testcontent == {}:
                                        print("No testdata for TARGET")
                                        sys.exit(1)
                                    else:
                                        fname = "%d_" % (self.currid) + self.current_confdata['testfile'].replace(".yaml", "") + ".yaml"
                                        self.writetest(fname, self.testcontent)
                                        print("testfile written: %s" % (fname))
                                        self.testcontent = {}
                                if directives_defined or after_each_defined:
                                    self.currid = last_id  # next ids start
                                self.currid += 1
        # add after all directives with CURRID substitution
        if after_defined:
            after = after_tpl.ruleid_substitute(increment_id_after_sub=True, **{'CURRID': self.currid}) + "\n"
            self.content += after
            self.currid = after_tpl.get_last_id()

    def parseactions(self, action):
        """From a list of actions as str, return a single str for inclusion in the template"""
        res = ""
        for i in range(len(action)):
            if i == len(action) - 1:
                res += action[i]
            else:
                res += action[i] + ",\\\n" + self.indent

        return res

    def parsedirectives(self, directive):
        """From a list of directives as str, return a single str for inclusion in the template"""
        res = ""
        for i in range(len(directive)):
            if i == len(directive) - 1:
                res += directive[i]
            else:
                res += directive[i] + "\n"

        return res

    def genobject(self, o):
        """generate an object, eg. 'secrule' or 'secaction'"""
        obj = ""
        objects = ""
        if o['object'].lower() == "secaction":
            obj += "SecAction \\\n"

        if o['object'].lower() == "secrule":
            obj += "SecRule %s \"%s\"\\\n" % (o['target'], o['operator'])

        if o['object'].lower() in ["secaction", "secrule"]:
            self.indentdepth += 1
            if 'actions' in o:
                objects = self.buildactions(o['actions'])
            self.indentdepth -= 1
        self.content += obj + objects + "\n\n"

    def writeconf(self, obj):
        """write the generated content"""
        try:
            with open(os.path.join(self.expdir, self.current_confdata['rulefile']), 'w') as fp:
                fp.write(obj)
        except Exception as e:
            print(", ".join(e.args))
            sys.exit(1)

    def writetest(self, fname, testobj):
        """write the generated test"""
        testcontent = yaml.dump(
            testobj,
            indent=2,
            sort_keys = False,
            default_flow_style = False,
            explicit_start = True
        )
        try:
            with open(os.path.join(self.testdir, fname), 'w') as fp:
                fp.write(testcontent)
        except Exception as e:
            print(", ".join(e.args))
            sys.exit(1)

    def buildactions(self, oa):
        """build the actionlist"""
        objacts = []
        aidx = 0
        for a in oa:
            if aidx == 0:
                quote = "\""
            else:
                quote = ""
            if oa[a] is not None:
                if isinstance(oa[a], int):
                    objacts.append("%s%s%s:%d" % (self.indentdepth*self.indent, quote, a, oa[a]))
                elif isinstance(oa[a], str):
                    objacts.append("%s%s%s:%s" % (self.indentdepth*self.indent, quote, a, oa[a]))
            else:
                objacts.append("%s%s%s" % (self.indentdepth*self.indent, quote, a))
            aidx += 1
        objacts = ",\\\n".join(objacts)
        return objacts + "\""


class RuleGeneratorTemplate(string.Template):
    pattern = r'''
    \${(?:
       (?P<escaped>\$) |               
       (?P<named>[^ \n\t$,'"]*)\}\$ |    
       \b\B(?P<braced>) |             
       (?P<invalid>)                  
    )
    '''

    def __init__(self, template):
        super().__init__(template)
        self.last_id = 0

    def get_last_id(self):
        return self.last_id

    def ruleid_substitute(self, increment_id_after_sub=False, **kwargs):
        """Increments CURRID before or after each substitution for macros"""
        def incrementing_substitution(match):
            var_name = match.group('named')
            if var_name == 'CURRID':
                if increment_id_after_sub:
                    kwargs['CURRID'] += 1
                    self.last_id = kwargs['CURRID']
                    return str(kwargs['CURRID'] - 1)
                else:  # increment before substitution
                    kwargs['CURRID'] += 1
                    self.last_id = kwargs['CURRID']
                    return str(kwargs['CURRID'])
            elif var_name in kwargs:
                return str(kwargs[var_name])
            else:
                return match.group(0)

        return re.compile(self.pattern).sub(incrementing_substitution, self.template)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="MRTS rule generate tool")
    parser.add_argument("-r", "--rulesdef", metavar='/path/to/mrts/*.yaml', type=str,
                            nargs='*', help='Directory path to MRTS rules definition', required=True,
                            action="append")
    parser.add_argument("-e", "--expdir", metavar='/path/to/mrts/rules/', type=str,
                            help='Directory path to generated MRTS rules', required=True)
    parser.add_argument("-t", "--testdir", metavar='/path/to/mrts/tests/', type=str,
                            help='Directory path to generated MRTS tests', required=True)
    args = parser.parse_args()

    mrtspath = []
    for l in args.rulesdef:
        mrtspath += l

    retval = 0
    try:
        flist = mrtspath
        flist.sort()
    except:
        print("Can't open files in given path!")
        sys.exit(1)

    if len(flist) == 0:
        print("List of files is empty!")
        sys.exit(1)

    gen = RuleGenerator(flist, args.expdir, args.testdir)


    sys.exit(retval)
