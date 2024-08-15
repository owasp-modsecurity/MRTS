#!/usr/bin/env python3

import argparse
import sys
import yaml
import os
import os.path
import string
import re
import copy

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
        self.default_oprator  = "@rx"
        self.confdata         = {
            'target'       : None,
            'rulefile'     : None,
            'testfile'     : None,
            'templates'    : [],
            'colkey'       : [],
            'operator'     : self.default_oprator,
            'oparg'        : "attack",
            'phase'        : [1,2,3,4],
            'phase_methods': {}
        }
        self.default_test_phase_methods = {
            1: "get",
            2: "post",
            3: "post",
            4: "post",
            5: "post"
        }

        self.current_confdata = {}
        self.current_testdata = {}

        self.indent           = "    "
        self.indentdepth      = 0
        self.expdir           = expdir
        self.testdir          = testdir
        self.content          = ""
        self.testcontent      = {}

        self.re_tplvars  = re.compile(r"""\$[^ \n\t$,'"]*""")

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

        # walk throug the files and process them
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

    def genrulefromtemplate(self, tpl, current_confdata):
        """
            generate a rule from data based on the template
            tpl: applied template
            current_confdata: content of processing file
        """

        # get the template vars; 'colkey' is not a tpl variable, but
        # needs for TARGET:colkey variables
        tplvars = [t.replace("$", "").lower() for t in self.re_tplvars.findall(tpl)]
        tplvars.append('colkey')

        ruletpl = string.Template(tpl)

        # build a dict for template vars
        tpldict = {}
        for t in tplvars:
            if t in current_confdata:
                tpldict[t] = current_confdata[t]
            elif hasattr(self, t):
                tpldict[t] = getattr(self, t)

        # current rule id
        tpldict['currid'] = self.currid

        # iterate loops through possible combinations of arguments
        # which are 'colkey', 'operator', 'oparg' and 'phase'
        # this 4 loop produces the combinations
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
                        td = {}
                        for k in tdict:
                            td[k.upper()] = tdict[k]
                        td['CURRID'] = self.currid
                        rule = ruletpl.substitute(**td) + "\n"
                        self.content += rule

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
                                            if self.current_testdata['phase_methods'][phase].lower() == "post":
                                                if isinstance(test['test']['data'], dict):
                                                    ik, iv = list(test['test']['data'].items())[0]
                                                    item['stages'][0]['input']['data'] = "%s=%s" % (ik, iv)
                                                elif isinstance(test['test']['data'], str):
                                                    item['stages'][0]['input']['data'] = "%s" % (test['test']['data'])
                                                item['stages'][0]['input']['uri'] = "/post"
                                            if self.current_testdata['phase_methods'][phase].lower() == "get":
                                                if isinstance(test['test']['data'], dict):
                                                    ik, iv = list(test['test']['data'].items())[0]
                                                    item['stages'][0]['input']['uri'] = "/?%s=%s" % (ik, iv)
                                            # add headers if there are
                                            if 'input' in test['test']:
                                                if 'headers' in test['test']['input']:
                                                    for h in test['test']['input']['headers']:
                                                        item['stages'][0]['input']['headers'][h['name']] = h['value']
                                            item['stages'][0]['output']['log']['expect_ids'].append(self.currid)
                                            self.testcontent['tests'].append(item)
                                            testcnt += 1
                            # if no testdata
                            if self.testcontent == {}:
                                print("No testdata for TARGET")
                                sys.exit(1)
                            else:
                                fname = self.current_confdata['testfile'].replace(".yaml", "") + "_%d.yaml" % (self.currid)
                                self.writetest(fname, self.testcontent)
                                print("testfile written: %s" % (fname))
                                self.testcontent = {}

                        self.currid += 1

    def genobject(self, o):
        """generat an object, eg. 'secrule' or 'secaction'"""
        obj = ""
        objacts = ""
        if o['object'].lower() == "secaction":
            obj += "SecAction \\\n"

        if o['object'].lower() == "secrule":
            obj += "SecRule %s \"%s\"\\\n" % (o['target'], o['operator'])

        if o['object'].lower() in ["secaction", "secrule"]:
            self.indentdepth += 1
            if 'actions' in o:
                objacts = self.buildactions(o['actions'])
            self.indentdepth -= 1
        self.content += obj + objacts + "\n\n"

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