#!/usr/bin/python2 -tt
# -*- coding: utf-8 -*-
# ^^-- use utf-8 strings by default
#-- NOTE: Tabs and spaces do NOT mix!! '-tt' will flag violations as an error.
#===============================================================================
'''
    :program:`sat6-host.py`
    ============================================================

    In addition to the options listed in help output, :program:`sat6-host.py` includes
    the following 'hidden' optoins:

    .. option:: --help-rest

        Output usage information in Sphinx/reST-style markup.

    .. option:: --debug

        Output debug-level information.

    :synopsis: TODO: CHANGEME

    :copyright: 2018 awmyhr
    :license: Apache-2.0

    .. codeauthor:: awmyhr <awmyhr@gmail.com>
'''
#===============================================================================
#-- Standard Imports
#-- NOTE: See __future__ documentation at https://docs.python.org/2/library/__future__.html
#--       This allows us to write Python 3 code for older version.
from __future__ import absolute_import  #: Require parens to group imports PEP-0328
from __future__ import division         #: Enable 3.x True Division PEP-0238
from __future__ import with_statement   #: Clean up some uses of try/except PEP--343
#-- These may break 2.5 compatibility
from __future__ import print_function   #: Makes print a function, not a statement PEP-3105
from __future__ import unicode_literals #: Introduce bytes type for older strings PEP-3112
import ConfigParser #: 'Easy' configuration parsing
#-- NOTE: We use optparse for compatibility with python < 2.7 as
#--       argparse wasn't standard until 2.7 (2.7 deprecates optparse)
#--       As of 20161212 the template is coded for optparse only
import optparse     #: pylint: disable=deprecated-module
import logging      #: Python's standard logging facilities
import os           #: Misc. OS interfaces
import sys          #: System-specific parameters & functions
# import traceback    #: Print/retrieve a stack traceback
#==============================================================================
#-- Additional Imports
#==============================================================================
#-- Imports needed for Sat6Object
try:
    import base64
except ImportError:
    raise ImportError('The python-base64 module is required.')
try:
    import requests
except ImportError:
    raise ImportError('The python-requests module is required.')
try:
    import json
except ImportError:
    raise ImportError('The python-json module is required.')
try:
    from urllib import urlencode
except ImportError:
    raise ImportError('The python-urllib module is required.')
try:
    from cookielib import LWPCookieJar
except ImportError:
    raise ImportError('The python-cookielib module is required.')
#==============================================================================
#-- Require a minimum Python version
if sys.version_info <= (2, 6):
    sys.exit("Minimum Python version: 2.6")
#-- NOTE: default Python versions:
#--       RHEL4    2.3.4
#--       RHEL5    2.4.3
#--       RHEL6.0  2.6.5
#--       RHEL6.1+ 2.6.6
#--       REHL7    2.7.5
#-- Recent Fedora versions (24/25) stay current on 2.7 (2.7.12 as of 20161212)
#==============================================================================
#==============================================================================
#-- Application Library Imports
#==============================================================================
#-- Variables which are meta for the script should be dunders (__varname__)
#-- TODO: Update meta vars
__version__ = '0.1.0-alpha' #: current version
__revised__ = '20181212-131535' #: date of most recent revision
__contact__ = 'awmyhr <awmyhr@gmail.com>' #: primary contact for support/?'s
__synopsis__ = 'TODO: CHANGEME'
__description__ = '''TODO: CHANGEME
'''
#------------------------------------------------------------------------------
#-- The following few variables should be relatively static over life of script
__author__ = ['awmyhr <awmyhr@gmail.com>'] #: coder(s) of script
__created__ = '2018-12-12'               #: date script originlly created
__copyright__ = '2018 awmyhr' #: Copyright short name
__license__ = 'Apache-2.0'
__gnu_version__ = False #: If True print GNU version string (which includes copyright/license)
__cononical_name__ = 'sat6-host.py' #: static name, *NOT* os.path.basename(sys.argv[0])
__project_name__ = 'The *NIXLand Satellite 6 Project'  #: name of overall project, if needed
__project_home__ = 'https://github.com/awmyhr/NSat6P'  #: where to find source/documentation
__template_version__ = '2.5.2'  #: version of template file used
#-- We are not using this variable for now.
__docformat__ = 'reStructuredText en'       #: attempted style for documentation
__basename__ = os.path.basename(sys.argv[0]) #: name script run as
#------------------------------------------------------------------------------
#-- Flags
__logger_file_set__ = False #: If a file setup for logger
__require_root__ = False    #: Does script require root
#------------------------------------------------------------------------------
#-- Load in environment variables, or set defaults
__default_dsf__ = os.getenv('DEFAULT_TIMESTAMP') if 'DEFAULT_TIMESTAMP' in os.environ else "%Y%m%d-%H%M%S"
__logger_dsf__ = os.getenv('LOGGER_DSF') if 'LOGGER_DSF' in os.environ else __default_dsf__
__backup_dsf__ = os.getenv('BACKUP_DSF') if 'BACKUP_DSF' in os.environ else __default_dsf__
__logger_file__ = os.getenv('LOGGER_FILE') if 'LOGGER_FILE' in os.environ else None
__logger_lvl__ = os.getenv('LOGGER_LVL') if 'LOGGER_LVL' in os.environ else 'info'

EXIT_STATUS = None
#==============================================================================
class _ModOptionParser(optparse.OptionParser):
    ''' By default format_epilog() strips newlines, we don't want that,
        so we override.
    '''

    def format_epilog(self, formatter):
        ''' We'll preformat the epilog in the decleration, just pass it through '''
        return self.epilog


#==============================================================================
class _ReSTHelpFormatter(optparse.HelpFormatter):
    ''' Format help for Sphinx/ReST output.

    NOTE: All over-ridden methods started life as copy'n'paste from original's
          source code.

    '''

    def __init__(self, indent_increment=0, max_help_position=4, width=80, short_first=0):
        optparse.HelpFormatter.__init__(self, indent_increment,
                                        max_help_position, width, short_first
                                       )

    def format_usage(self, usage):
        retval = ['%s\n' % ('=-'[self.level] * len(__cononical_name__))]
        retval.append('%s\n' % (__cononical_name__))
        retval.append('%s\n\n' % ('=-'[self.level] * len(__cononical_name__)))
        retval.append('%s' % self.format_heading('Synopsis'))
        retval.append('**%s** %s\n\n' % (__cononical_name__, usage))
        return ''.join(retval)

    def format_heading(self, heading):
        return '%s\n%s\n\n' % (heading, '--'[self.level] * len(heading))

    def format_description(self, description):
        if description:
            retval = ['%s' % self.format_heading('Description')]
            retval.append('%s\n' % self._format_text(description))
            return ''.join(retval)
        return ''

    def format_option(self, option):
        opts = self.option_strings[option]
        retval = ['.. option:: %s\n\n' % opts]
        if option.help:
            # help_text = self.expand_default(option)
            # help_lines = textwrap.wrap(help_text, self.help_width)
            retval.append('%4s%s\n\n' % ('', self.expand_default(option)))
            # retval.extend(['%4s%s\n' % ('', line)
            #                for line in help_lines[1:]])
        elif opts[-1] != '\n':
            retval.append('\n')
        return ''.join(retval)

    def format_option_strings(self, option):
        ''' Return a comma-separated list of option strings & metavariables. '''
        if option.takes_value():
            metavar = option.metavar or option.dest.upper()
            short_opts = ['%s <%s>' % (sopt, metavar)
                          for sopt in option._short_opts] #: pylint: disable=protected-access
                                                          #: We're over-riding the default
                                                          #:    method, keeping most the code.
                                                          #:    Not sure how else we'd do this.
            long_opts = ['%s=<%s>' % (lopt, metavar)
                         for lopt in option._long_opts]   #: pylint: disable=protected-access
        else:
            short_opts = option._short_opts               #: pylint: disable=protected-access
            long_opts = option._long_opts                 #: pylint: disable=protected-access

        if self.short_first:
            opts = short_opts + long_opts
        else:
            opts = long_opts + short_opts

        return ', '.join(opts)


#==============================================================================
class colors(object):
    ''' Simple class to ease access to ENV colors '''
    _colorlist = ['cf_black', 'cf_white', 'cf_orange', 'cf_magenta',
                  'cf_yellow', 'cf_red', 'cf_purple', 'cf_blue',
                  'cf_cyan', 'cf_green',
                  'c_bold', 'c_reset', 'c_undr', 'c_hide',
                  'c_blik', 'c_revr'
                 ]
    _colors = {}

    def __init__(self):
        for color in self._colorlist:
            self._colors[color] = os.getenv(color) if color in os.environ else ''

    @classmethod
    def load_colors(cls):
        ''' This will load colors from a file someday '''
        for color in cls._colorlist:
            cls._colors[color] = os.getenv(color) if color in os.environ else ''

    @classmethod
    def clear_colors(cls):
        ''' This will reset all colors to empty '''
        pass

    @property
    def black(self):
        ''' Instance property '''
        if 'cf_black' in self._colors:
            return self._colors['cf_black']
        return ''

    @property
    def white(self):
        ''' Instance property '''
        if 'cf_white' in self._colors:
            return self._colors['cf_white']
        return ''

    @property
    def magenta(self):
        ''' Instance property '''
        if 'cf_magenta' in self._colors:
            return self._colors['cf_magenta']
        return ''

    @property
    def orange(self):
        ''' Instance property '''
        if 'cf_orange' in self._colors:
            return self._colors['cf_orange']
        return ''

    @property
    def red(self):
        ''' Instance property '''
        if 'cf_red' in self._colors:
            return self._colors['cf_red']
        return ''

    @property
    def yellow(self):
        ''' Instance property '''
        if 'cf_yellow' in self._colors:
            return self._colors['cf_yellow']
        return ''

    @property
    def purple(self):
        ''' Instance property '''
        if 'cf_purple' in self._colors:
            return self._colors['cf_purple']
        return ''

    @property
    def blue(self):
        ''' Instance property '''
        if 'cf_blue' in self._colors:
            return self._colors['cf_blue']
        return ''

    @property
    def cyan(self):
        ''' Instance property '''
        if 'cf_cyan' in self._colors:
            return self._colors['cf_cyan']
        return ''

    @property
    def green(self):
        ''' Instance property '''
        if 'cf_green' in self._colors:
            return self._colors['cf_green']
        return ''

    @property
    def bold(self):
        ''' Instance property '''
        if 'c_bold' in self._colors:
            return self._colors['c_bold']
        return ''

    @property
    def reset(self):
        ''' Instance property '''
        if 'c_reset' in self._colors:
            return self._colors['c_reset']
        return ''

    @property
    def undr(self):
        ''' Instance property '''
        if 'c_undr' in self._colors:
            return self._colors['c_undr']
        return ''

    @property
    def hide(self):
        ''' Instance property '''
        if 'c_hide' in self._colors:
            return self._colors['c_hide']
        return ''

    @property
    def blik(self):
        ''' Instance property '''
        if 'c_blik' in self._colors:
            return self._colors['c_blik']
        return ''

    @property
    def revr(self):
        ''' Instance property '''
        if 'c_revr' in self._colors:
            return self._colors['c_revr']
        return ''


#==============================================================================
def timestamp(time_format=None):
    ''' Return date in specified format

    Args:
        time_format (str): Format string for timestamp. Compatible w/'date'.

    Returns:
        The formatted timestamp as a string.

    '''
    if 'logger' in globals():
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    import time
    if time_format is None:
        time_format = __default_dsf__
    return time.strftime(time_format.strip('+'))


#==============================================================================
def get_temp(directory=None):
    ''' Creates a temporary file (or directory), returning the path.
        Defaults to file.

    Args:
        program (str): Name of program to find.

    Returns:
        For directory: absolute path to directory as a string.
        For a file: a tuple with OS-level handle to an open file.

    '''
    if 'logger' in globals():
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    import tempfile
    if directory is not None and directory.lower() in 'directory':
        return tempfile.mkdtemp(prefix='%s-d.' % __cononical_name__)
    return tempfile.mkstemp(prefix='%s.' % __cononical_name__)


#==============================================================================
def set_value(filename, key, value):
    ''' Add or change a KEY to a VALUE in a FILE, creating FILE if necessary.

    Args:
        filename (str): File to create/modify
        key (str) :     Key to create/modify
        value (str):    Value to set key to

    Returns:
        Success/failure as a Boolean.

    '''
    if 'logger' in globals():
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        logger.debug('Passed: file: %s, key: %s, value: %s', filename, key, value)
    raise NotImplementedError('TODO: implement set_value().')

#==============================================================================
def RunLogger(debug=False):
    ''' Set up Python's Logging

    Args:
        debug (boolean): Debug flag.

    Returns:
        The logging object.

    '''
    new_logger = logging.getLogger(__name__)
    new_logger.setLevel(logging.DEBUG)

    if debug:
        level = logging.DEBUG
        formatter = logging.Formatter('%(asctime)s %(levelname)-8s %(message)s',
                                      __logger_dsf__
                                     )
    else:
        if __logger_lvl__.isdigit():
            if int(__logger_lvl__) > 49:
                level = logging.CRITICAL
            elif int(__logger_lvl__) < 10:
                level = logging.NOTSET
            else:
                level = (int(__logger_lvl__)) //10 * 10
        else:
            level = logging.getLevelName(__logger_lvl__.upper())
        #-- Yes, we are going to ignore unknown values by setting to INFO
        if isinstance(level, str) and level.startswith('Level'):
            level = logging.INFO
        formatter = logging.Formatter('%(message)s')

    #-- Console output
    console = logging.StreamHandler()
    console.setLevel(level)
    console.setFormatter(formatter)
    new_logger.addHandler(console)

    #-- File output
    if __logger_file__:
        if os.path.isfile(__logger_file__):
            os.rename(__logger_file__, '%s.%s' % (__logger_file__, timestamp(__backup_dsf__)))
        #: NOTE: In Python >= 2.6 normally I give FileHandler 'delay="true"'
        logfile = logging.FileHandler(__logger_file__)
        logfile.setLevel(logging.DEBUG)
        formatter = logging.Formatter(
            '%(asctime)s.%(msecs)d:%(levelno)s:%(name)s.%(funcName)s:%(lineno)d:%(message)s',
            __logger_dsf__
            )
        logfile.setFormatter(formatter)
        new_logger.addHandler(logfile)
        global __logger_file_set__               #: pylint: disable=global-statement
        __logger_file_set__ = True

    import platform #: Easily get platforms identifying info
    new_logger.debug('Version:   %s (%s) %s', __cononical_name__, __project_name__, __version__)
    new_logger.debug('Created:   %s / Revised: %s', __created__, __revised__)
    new_logger.debug('Abs Path:  %s', os.path.abspath(sys.argv[0]))
    new_logger.debug('Full Args: %s', ' '.join(sys.argv[:]))
    new_logger.debug('Python:    %s (%s)', sys.executable, platform.python_version())
    new_logger.debug('Coder(s):  %s', __author__)
    new_logger.debug('Contact:   %s', __contact__)
    new_logger.debug('Project Home: %s', __project_home__)
    new_logger.debug('Template Version: %s', __template_version__)
    new_logger.debug('System:    %s', platform.system_alias(platform.system(),
                                                            platform.release(),
                                                            platform.version()
                                                           )
                    )
    new_logger.debug('Platform:  %s', platform.platform())
    new_logger.debug('Hostname:  %s', platform.node())
    new_logger.debug('Logname:   %s', os.getlogin())
    new_logger.debug('[re]uid:  %s/%s', os.getuid(), os.geteuid())
    new_logger.debug('PID/PPID:  %s/%s', os.getpid(), os.getppid())
    if options._options is not None:             #: pylint: disable=protected-access
        new_logger.debug('Parsed Options: %s', options._options) #: pylint: disable=protected-access
    if debug:
        print('\n----- start -----\n')

    return new_logger


#==============================================================================
def which(program):
    '''Test if a program exists in $PATH.

    Args:
        program (str): Name of program to find.

    Returns:
        String to use for program execution.

    Note:
        Originally found this here:
        http://stackoverflow.com/questions/377017/test-if-executable-exists-in-python
    '''
    logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    logger.debug('Looking for command: %s', program)
    def _is_exe(fpath):
        ''' Private test for executeable '''
        return os.path.isfile(fpath) and os.access(fpath, os.X_OK)

    fpath, _ = os.path.split(program)
    if fpath:
        if _is_exe(program):
            logger.debug('Found %s here.', program)
            return program
    else:
        for path in os.environ["PATH"].split(os.pathsep):
            path = path.strip('"')
            exe_file = os.path.join(path, program)
            if _is_exe(exe_file):
                logger.debug('Found %s here: %s', program, exe_file)
                return exe_file

    logger.debug('Could not find %s.', program)
    return None


#==============================================================================
class RunOptions(object):
    ''' Parse the options and put them into an object

        Returns:
            A RunOptions object.

    '''
    _defaults = {
        'debug': False,
    }

    _arguments = None
    _configs = None
    _options = None

    def __init__(self, args=None):
        if self._configs is not None:
            raise ValueError('Configs already initialized.')
        else:
            self._configs = self._load_configs()
        if self._options is not None:
            raise ValueError('Arguments already initialized.')
        else:
            (self._options, self._arguments) = self._parse_args(args)

    def _load_configs(self):
        parser = ConfigParser.SafeConfigParser(defaults=self._defaults)
        parser.read([os.path.expanduser('~/.%s' % __cononical_name__),
                     '%s.cfg' % __cononical_name__])
        #-- TODO: Define possible sections
        if not parser.has_section('debug'):
            parser.add_section('debug')
        return parser

    @property
    def args(self):
        ''' Class property '''
        if self._arguments is not None:
            return self._arguments
        return None

    @property
    def debug(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.debug
        return self._defaults['debug']

    @property
    def ansible_called(self):
        ''' Class property '''
        return bool(__basename__.startswith('ansible_module'))

    def _parse_args(self, args):
        #-- Parse Options (rely on OptionsParser's exception handling)
        description_string = __synopsis__
        epilog_string = ('\n%s\n\n'
                         'Created: %s  Contact: %s\n'
                         'Revised: %s  Version: %s\n'
                         '%s, part of %s. Project home: %s\n'
                        ) % (__description__,
                             __created__, __contact__,
                             __revised__, __version__,
                             __cononical_name__, __project_name__, __project_home__
                            )
        usage_string = '%s [options]' % (__basename__)
        version_string = '%s (%s) %s' % (__cononical_name__, __project_name__, __version__)
        if __gnu_version__:
            version_string += '\nCopyright %s\nLicense %s\n' % (__copyright__, __license__)
        parser = _ModOptionParser(version=version_string, usage=usage_string,
                                  description=description_string, epilog=epilog_string)
        #-- TODO: Add options, also set _default and @property (if needed).
        #-- Visible Options
        #   These can *not* be set in a config file
        #   These could be set in a config file

        #-- Hidden Options
        #   These can *not* be set in a config file
        parser.add_option('--help-rest', dest='helprest', action='store_true',
                          help=optparse.SUPPRESS_HELP, default=None)
        #   These could be set in a config file
        parser.add_option('--debug', dest='debug', action='store_true',
                          help=optparse.SUPPRESS_HELP,
                          default=self._configs.get('debug', 'debug'))

        parsed_opts, parsed_args = parser.parse_args(args)
        if parsed_opts.helprest:
            parser.formatter = _ReSTHelpFormatter()
            parser.usage = '[*options*]'         #: pylint: disable=attribute-defined-outside-init
                                                 #: Not yet sure of a better way to do this...
            parser.description = __description__ #: pylint: disable=attribute-defined-outside-init
            parser.epilog = '\nAuthor\n------\n\n%s\n' % ('; '.join(__author__))
            parser.print_help()
            sys.exit(os.EX_OK)
        #-- Put any option validation here...

        return parsed_opts, parsed_args


#==============================================================================
class Sat6Object(object):
    ''' Class for interacting with Satellite 6 API '''
    __version = '1.5.0'
    #-- Max number of items returned per page.
    #   Though we allow this to be configured, KB articles say 100 is the
    #   optimal value to avoid timeouts.
    per_page = 100
    lookup_tables = {'lce': 'lut/lce_name.json'}

    def __init__(self, server=None, username=None, password=None,
                 authkey=None, org_id=None, org_name=None, insecure=False):
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        logger.debug('Initiallizing Sat6Object version %s.', self.__version)
        if authkey is None:
            if username is None or password is None:
                raise RuntimeError('Must provide either authkey or username/password pair.')
            logger.debug('Creating authkey for user: %s', username)
            self.username = username
            self.authkey = base64.b64encode('%s:%s' % (username, password)).strip()
        else:
            self.authkey = authkey
        if server is None:
            raise RuntimeError('Must provide Satellite server name.')
        self.server = server
        self.url = 'https://%s' % server
        self.pub = '%s/pub' % self.url
        self.foreman = '%s/api/v2' % self.url
        self.katello = '%s/katello/api' % self.url
        self.insecure = insecure
        self.connection = self._new_connection()
        self.results = {"success": None, "msg": None, "return": None}
        self.lutables = {}
        self.verbose = False
        if org_name is not None:
            self.org_name = org_name
            self.org_id = self.get_org(self.org_name)['id']
        elif org_id is not None:
            self.org_id = org_id
        else:
            self.org_id = 1

    def __del__(self):
        self.connection.cookies.save(ignore_discard=True)

    #===============================================================================
    #-- The following originates from a  StackOverflow thread titled
    #   "Check if a string matches an IP address pattern in Python".
    #   We are only interested in valid IPv4 addresses.
    #===============================================================================
    # https://stackoverflow.com/questions/3462784/check-if-a-string-matches-an-ip-address-pattern-in-python
    #===============================================================================
    @classmethod
    def _is_valid_ipv4(cls, ipaddr):
        '''Checks if passed paramater is a valid IPv4 address'''
        parts = ipaddr.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) < 256 for p in parts)
        except ValueError:
            return False

    def _get_rest_call(self, url, params=None, data=None):
        ''' Call a REST API URL using GET.

        Args:
            session_obj (obj): Session object
            url (str):         URL of API
            params (dict):     Dict of params to pass to Requests.get

        Returns:
            Results of API call in a dict

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access

        logger.debug('Calling URL: %s', url)
        logger.debug('With Headers: %s', self.connection.headers)
        if params is not None:
            logger.debug('With params: %s', params)
        if data is not None:
            logger.debug('With data: %s', data)
            data = json.dumps(data)

        try:
            results = self.connection.get(url, params=params, data=data)
            logger.debug('Final URL: %s', results.url)
            logger.debug('Return Headers: %s', results.headers)
            logger.debug('Status Code: %s', results.status_code)
            if self.verbose:
                logger.debug('Raw return: %s', results.raw)
        except requests.ConnectionError as error:
            logger.debug('Caught Requests Connection Error.')
            error.message = '[ConnectionError]: %s' % (error.message) #: pylint: disable=no-member
            raise error
        except requests.HTTPError as error:
            logger.debug('Caught Requests HTTP Error.')
            error.message = '[HTTPError]: %s' % (error.message) #: pylint: disable=no-member
            raise error
        except requests.Timeout as error:
            logger.debug('Caught Requests Timeout.')
            error.message = '[Timeout]: %s' % (error.message) #: pylint: disable=no-member
            raise error
        except Exception as error:
            logger.debug('Caught Requests Exception.')
            error.message = '[Requests]: REST call failed: %s' % (error.message) #: pylint: disable=no-member
            raise error
        results.raise_for_status()

        rjson = results.json()
        if self.verbose:
            logger.debug('Results: %s', rjson)

        if rjson.get('error'):
            logger.debug('Requests API call returned error.')
            raise IOError(127, '[Requests]: API call failed: %s' % (rjson['error']['message']))
        return rjson

    def _put_rest_call(self, url, data=None):
        ''' Call a REST API URL using PUT .

        Args:
            session_obj (obj): Session object
            url (str):         URL of API
            data (dict):       Dict of data to pass to Requests.put

        Returns:
            Results of API call in a dict

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access

        logger.debug('Calling URL: %s', url)
        if data is not None:
            logger.debug('With data: %s', data)
            data = json.dumps(data)

        try:
            results = self.connection.put(url, data=data)
            logger.debug('Final URL: %s', results.url)
            logger.debug('Return Headers: %s', results.headers)
            logger.debug('Status Code: %s', results.status_code)
            if self.verbose:
                logger.debug('Raw results: %s', results.raw)
        except requests.ConnectionError as error:
            logger.debug('Caught Requests Connection Error.')
            error.message = '[ConnectionError]: %s' % (error.message) #: pylint: disable=no-member
            raise error
        except requests.HTTPError as error:
            logger.debug('Caught Requests HTTP Error.')
            error.message = '[HTTPError]: %s' % (error.message) #: pylint: disable=no-member
            raise error
        except requests.Timeout as error:
            logger.debug('Caught Requests Timeout.')
            error.message = '[Timeout]: %s' % (error.message) #: pylint: disable=no-member
            raise error
        except Exception as error:
            logger.debug('Caught Requests Exception.')
            error.message = '[Requests]: REST call failed: %s' % (error.message) #: pylint: disable=no-member
            raise error
        results.raise_for_status()

        rjson = results.json()
        if self.verbose:
            logger.debug('Results: %s', rjson)

        if 'error' in rjson:
            logger.debug('Requests API call returned error.')
            raise IOError(127, '[Requests]: API call failed: %s' % (rjson['error']['message']))
        return rjson

    def _post_rest_call(self, url, data=None):
        ''' Call a REST API URL using POST .

        Args:
            session_obj (obj): Session object
            url (str):         URL of API
            data (dict):       Dict of data to pass to Requests.put

        Returns:
            Results of API call in a dict

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access

        logger.debug('Calling URL: %s', url)
        if data is not None:
            logger.debug('With data: %s', data)
            data = json.dumps(data)

        try:
            results = self.connection.post(url, data=data)
            logger.debug('Final URL: %s', results.url)
            logger.debug('Return Headers: %s', results.headers)
            logger.debug('Status Code: %s', results.status_code)
            if self.verbose:
                logger.debug('Raw results: %s', results.raw)
        except requests.ConnectionError as error:
            logger.debug('Caught Requests Connection Error.')
            error.message = '[ConnectionError]: %s' % (error.message) #: pylint: disable=no-member
            raise error
        except requests.HTTPError as error:
            logger.debug('Caught Requests HTTP Error.')
            error.message = '[HTTPError]: %s' % (error.message) #: pylint: disable=no-member
            raise error
        except requests.Timeout as error:
            logger.debug('Caught Requests Timeout.')
            error.message = '[Timeout]: %s' % (error.message) #: pylint: disable=no-member
            raise error
        except Exception as error:
            logger.debug('Caught Requests Exception.')
            error.message = '[Requests]: REST call failed: %s' % (error.message) #: pylint: disable=no-member
            raise error
        results.raise_for_status()

        rjson = results.json()
        if self.verbose:
            logger.debug('Results: %s', rjson)

        if 'error' in rjson:
            logger.debug('Requests API call returned error.')
            raise IOError(127, '[Requests]: API call failed: %s' % (rjson['error']['message']))
        return rjson

    def _new_connection(self, authkey=None, insecure=None, token=None, client_id=None):
        ''' Create a Request session object

        Args:
            authkey (str): Username

        Returns:
            Requests session object.

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        if authkey is None:
            authkey = self.authkey
        if token is None:
            authorization = 'Basic %s' % authkey
        else:
            authorization = 'Bearer %s' % token['access_token']
        if insecure is None:
            verify = not bool(self.insecure)
        else:
            verify = not bool(insecure)
        connection = requests.Session()
        connection.headers = {
            'x-ibm-client-id': client_id,
            'content-type': 'application/json',
            'authorization': authorization,
            'accept': 'application/json',
            'cache-control': 'no-cache'
        }
        logger.debug('Headers set: %s', connection.headers)
        connection.verify = verify
        connection.cookies = LWPCookieJar(os.getenv("HOME") + "/.sat6_api_session")
        try:
            connection.cookies.load(ignore_discard=True)
        except IOError:
            pass

        return connection

    # def _get_cookies(self):
    #     ''' Handle session cookie '''
    #     logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    #     self.cookies = LWPCookieJar(os.getenv("HOME") + "/.sat6_api_session")
    #     try:
    #         self.cookies.load(ignore_discard=True)
    #     except IOError:
    #         pass
    #     return self.cookies

    def lookup_lce_name(self, lce_tag):
        ''' Searches for and returns LCE from Satellite 6.
            This is a highly-custom routine which depends on a lookup-table
            existing as a static json file in the Satellites pub directory.
            The json file is a simple, manually maintained list of possible
            search phrases mapped to actual LCE names.

        Args:
            lce_tag (str):        Name of LCE find.

        Returns:
            Satellite 6 name of LCE.

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        logger.debug('Looking for lce: %s', lce_tag)

        if 'lce' not in self.lutables:
            logger.debug('First time calling function, loading table.')
            self.lutables['lce'] = self._get_rest_call('%s/%s' % (self.pub,
                                                                  self.lookup_tables['lce']))
            if '_revision' in self.lutables['lce']:
                logger.debug('LCE Table revision: %s', self.lutables['lce']['_revision'])
            else:
                logger.debug('Warning: LCE Table did not have _revision tag.')
        return self.lutables['lce'].get(lce_tag.lower(), None)

    def get_host(self, hostname):
        ''' Searches for and returns info for a Satellite 6 host.

        Args:
            hostname (str):        Name of host to find.

        Returns:
            Info for a host (dict). Of particular value may be
            return['certname']
            return['content_facet_attributes']['content_view']['id']
            return['content_facet_attributes']['content_view']['name']
            return['content_facet_attributes']['lifecycle_environment']['id']
            return['content_facet_attributes']['lifecycle_environment']['name']
            return['content_host_id']
            return['id']
            return['subscription_status']
            return['organization_name']
            return['organization_id']

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        logger.debug('Looking for host: %s', hostname)
        self.results = {"success": None, "msg": None, "return": None}
        if hostname is None:
            self.results['success'] = False
            self.results['msg'] = 'Error: Hostname passed was type None.'
        else:
            if isinstance(hostname, int):
                results = self._get_rest_call('%s/hosts/%s' % (self.foreman, hostname))
                if 'error' in results:
                    #-- This is not likely to execute, as if the host ID is not
                    #   found a 404 is thrown, which is caught by the exception
                    #   handling mechanism, and the program will bomb out.
                    #   Not sure I want to change that...
                    self.results['success'] = False
                    self.results['msg'] = 'Warning: No host ID %s.' % hostname
                    self.results['return'] = results
                else:
                    self.results['success'] = True
                    self.results['msg'] = 'Success: Host ID %s found.' % hostname
                    self.results['return'] = results
            else:
                if not self._is_valid_ipv4(hostname):
                    hostname = hostname.split('.')[0]
                results = self._get_rest_call('%s/hosts' % (self.foreman),
                                              {'search':  'name~%s' % hostname})
                if results['subtotal'] == 0:
                    self.results['success'] = False
                    self.results['msg'] = 'Warning: No host matches for %s.' % hostname
                    self.results['return'] = results['results']
                elif results['subtotal'] > 1:
                    self.results['success'] = False
                    self.results['msg'] = 'Warning: Too many host matches for %s (%s).' % (hostname, results['total'])
                    self.results['return'] = results['results']
                else:
                    self.results['success'] = True
                    self.results['msg'] = 'Success: Hostname %s found.' % hostname
                    self.results['return'] = self._get_rest_call('%s/hosts/%s' % (self.foreman, results['results'][0]['id']))

        logger.debug(self.results['msg'])
        if self.results['success']:
            return self.results['return']
        return None

    def get_host_list(self):
        ''' This returns a list of Satellite 6 Hosts.

        Returns:
            List of Hosts (dict). Of particular value will be

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        item = 0
        page_item = 0
        page = 1

        results = self._get_rest_call('%s/hosts' % (self.foreman),
                                      {'page': page, 'per_page': self.per_page})
        while item < results['subtotal']:
            if page_item == self.per_page:
                page += 1
                page_item = 0
                results = self._get_rest_call('%s/hosts' % (self.foreman),
                                              {'page': page, 'per_page': self.per_page})
            yield results['results'][page_item]
            item += 1
            page_item += 1

    def get_cv_list(self):
        ''' This returns a list of Satellite 6 content views.

        Returns:
            List of Orgs (dict). Of particular value will be

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        item = 0
        page_item = 0
        page = 1

        results = self._get_rest_call('%s/content_views' % (self.katello),
                                      {'page': page, 'per_page': self.per_page})
        while item < results['subtotal']:
            if page_item == self.per_page:
                page += 1
                page_item = 0
                results = self._get_rest_call('%s/content_views' % (self.katello),
                                              {'page': page, 'per_page': self.per_page})
            yield results['results'][page_item]
            item += 1
            page_item += 1

    def get_hc(self, collection=None):
        ''' Returns info about a Satellite 6 collection.
            If collection is an integer (i.e., self.org_id), will return
            detailed info about that specific org.
            Otherwise will run a search for string passed. If only one result
            is found, will return some very basic info about said org.

        Args:
            collection (str/int): Name of collection to find.

        Returns:
            Basic info of collection (dict). Of particular value may be
            return['name']
            return['id']
            return['title']
            return['label']
            return['description']

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        if collection is None:
            logger.debug('Was not given collection to find.')
            return None
        logger.debug('Looking for collection: %s', collection)
        self.results = {"success": None, "msg": None, "return": None}

        if isinstance(collection, int):
            results = self._get_rest_call('%s/host_collections/%s' % (self.katello, collection))
            if 'error' in results:
                #-- This is not likely to execute, as if the host ID is not
                #   found a 404 is thrown, which is caught by the exception
                #   handling mechanism, and the program will bomb out.
                #   Not sure I want to change that...
                self.results['success'] = False
                self.results['msg'] = 'Warning: No Collection ID %s.' % collection
                self.results['return'] = results
            else:
                self.results['success'] = True
                self.results['msg'] = 'Success: Collection ID %s found.' % collection
                self.results['return'] = results
        else:
            search_str = 'name~"%s"' % collection

            results = self._get_rest_call('%s/organizations/%s/host_collections/' % (self.katello, self.org_id),
                                          urlencode([('search', '' + str(search_str))]))
            if results['subtotal'] == 0:
                self.results['success'] = False
                self.results['msg'] = 'Warning: No collection matches for %s.' % collection
                self.results['return'] = results['results']
            elif results['subtotal'] > 1:
                self.results['success'] = False
                self.results['msg'] = 'Warning: Too many collection matches for %s (%s).' % (collection, results['total'])
                self.results['return'] = results['results']
                for result in results['results']:
                    if result['name'].lower() == collection.lower():
                        self.results['success'] = True
                        self.results['msg'] = 'Success: Collection %s found.' % collection
                        self.results['return'] = result
            else:
                self.results['success'] = True
                self.results['msg'] = 'Success: Collection %s found.' % collection
                self.results['return'] = results['results'][0]

        logger.debug(self.results['msg'])
        if self.results['success']:
            return self.results['return']
        return None

    def get_hc_list(self):
        ''' This returns a list of Satellite 6 content views.

        Returns:
            List of Orgs (dict). Of particular value will be

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        item = 0
        page_item = 0
        page = 1

        results = self._get_rest_call('%s/organizations/%s/host_collections' % (self.katello, self.org_id),
                                      {'page': page, 'per_page': self.per_page})
        while item < results['subtotal']:
            if page_item == self.per_page:
                page += 1
                page_item = 0
                results = self._get_rest_call('%s/organizations/%s/host_collections' % (self.katello, self.org_id),
                                              {'page': page, 'per_page': self.per_page})
            yield results['results'][page_item]
            item += 1
            page_item += 1

    def create_hc(self, collection):
        ''' Creates a host collection in the default organization

        Args:
            collection (str): Name of collection to create

        Returns:
            Basic info of collection created
        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        if collection is None:
            logger.debug('Was not given collection to create.')
            return None
        logger.debug('Creating collection: %s', collection)
        self.results = {"success": None, "msg": None, "return": None}

        check = self.get_hc(collection)
        if check:
            self.results['return'] = check
            self.results['success'] = True
            self.results['msg'] = 'Collection %s exists, nothing to do.' % (collection)
            return True

        results = self._post_rest_call('%s/organizations/%s/host_collections' % (self.katello, self.org_id),
                                       {'organization_id': self.org_id, 'name': collection})
        if results['id']:
            self.results['return'] = results
            self.results['success'] = True
            self.results['msg'] = 'Collection %s created.' % (collection)
            return True
        self.results['return'] = results
        self.results['success'] = False
        self.results['msg'] = 'Unable to create collection, reason unknown.'
        return False

    def get_org(self, organization=None):
        ''' Returns info about a Satellite 6 organization.
            If organization is an integer (i.e., self.org_id), will return
            detailed info about that specific org.
            Otherwise will run a search for string passed. If only one result
            is found, will return some very basic info about said org.

        Args:
            organization (str/int): Name of organization to find.

        Returns:
            Basic info of organization (dict). Of particular value may be
            return['name']
            return['id']
            return['title']
            return['label']
            return['description']

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        if organization is None:
            if self.org_id is None:
                organization = self.org_name
            else:
                organization = self.org_id
        logger.debug('Looking for organization: %s', organization)
        self.results = {"success": None, "msg": None, "return": None}

        if isinstance(organization, int):
            results = self._get_rest_call('%s/organizations/%s' % (self.katello, organization))
            if 'error' in results:
                #-- This is not likely to execute, as if the host ID is not
                #   found a 404 is thrown, which is caught by the exception
                #   handling mechanism, and the program will bomb out.
                #   Not sure I want to change that...
                self.results['success'] = False
                self.results['msg'] = 'Warning: No Organization ID %s.' % organization
                self.results['return'] = results
            else:
                self.results['success'] = True
                self.results['msg'] = 'Success: Organization ID %s found.' % organization
                self.results['return'] = results
        else:
            results = self._get_rest_call('%s/organizations' % (self.katello),
                                          {'search': organization})
            if results['subtotal'] == 0:
                self.results['success'] = False
                self.results['msg'] = 'Warning: No organization matches for %s.' % organization
                self.results['return'] = results['results']
            elif results['subtotal'] > 1:
                self.results['success'] = False
                self.results['msg'] = 'Warning: Too many organization matches for %s (%s).' % (organization, results['total'])
                self.results['return'] = results['results']
            else:
                self.results['success'] = True
                self.results['msg'] = 'Success: Organization %s found.' % organization
                self.results['return'] = results['results'][0]

        logger.debug(self.results['msg'])
        if self.results['success']:
            return self.results['return']
        return None

    def get_org_list(self):
        ''' This returns a list of Satellite 6 organizations.

        Returns:
            List of Orgs (dict). Of particular value will be

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        item = 0
        page_item = 0
        page = 1

        results = self._get_rest_call('%s/organizations' % (self.katello),
                                      {'page': page, 'per_page': self.per_page})
        while item < results['subtotal']:
            if page_item == self.per_page:
                page += 1
                page_item = 0
                results = self._get_rest_call('%s/organizations' % (self.katello),
                                              {'page': page, 'per_page': self.per_page})
            yield results['results'][page_item]
            item += 1
            page_item += 1

    def get_org_lce(self, lce_name, org_id=None):
        ''' This returns info about an Lifecycle Environments

        Args:
            lce_name: LCE name to lookup
            org_id:   Organization ID to check

        Returns:
            A dict of info about a LCE

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        if org_id is None:
            org_id = self.org_id
        logger.debug('Looking for Life Cycle Environment %s in org %s.', lce_name, org_id)
        self.results = {"success": None, "msg": None, "return": None}

        if lce_name is None:
            self.results['success'] = False
            self.results['msg'] = 'Error: lce_name passed was type None.'
        else:
            results = self._get_rest_call('%s/organizations/%s/environments' % (self.katello, org_id),
                                          {'search': '"%s"' % lce_name})
            if results['subtotal'] == 0:
                self.results['success'] = False
                self.results['msg'] = 'Error: No LCE matches for %s in org %s.' % lce_name, org_id
            elif results['subtotal'] > 1:
                self.results['success'] = False
                self.results['msg'] = 'Error: Too many LCE matches for %s in org %s.' % lce_name, org_id
            else:
                self.results['success'] = True
                self.results['msg'] = 'Success: Found LCE %s.' % lce_name
                self.results['return'] = results['results'][0]

        logger.debug(self.results['msg'])
        if self.results['success']:
            return self.results['return']
        return None

    def get_org_lce_list(self, org_id=None):
        ''' This returns a list of an Orgs Lifecycel Environments

        Args:
            org_id:           Organization ID to check

        Returns:
            List of LCEs (dict). Of particular value may be

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        if org_id is None:
            org_id = self.org_id
        logger.debug('Retriveing list of Lifecycle Environments for org_id %s.', org_id)
        item = 0
        page_item = 0
        page = 1

        results = self._get_rest_call('%s/organizations/%s/environments' % (self.katello, org_id),
                                      {'page': page, 'per_page': self.per_page})
        while item < results['subtotal']:
            if page_item == self.per_page:
                page += 1
                page_item = 0
                results = self._get_rest_call(
                    '%s/organizations/%s/environments' % (self.katello, org_id),
                    {'page': page, 'per_page': self.per_page})
            yield results['results'][page_item]
            item += 1
            page_item += 1

    def get_loc(self, location=None):
        ''' Returns info about a Satellite 6 location.
            If location is an integer (i.e., self.org_id), will return
            detailed info about that specific org.
            Otherwise will run a search for string passed. If only one result
            is found, will return some very basic info about said org.

        Args:
            location (str/int): Name of location to find.

        Returns:
            Basic info of location (dict). Of particular value may be
            return['name']
            return['id']
            return['title']
            return['label']
            return['description']

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        if location is None:
            logger.debug('Was not given location to find.')
            return None
        logger.debug('Looking for location: %s', location)
        self.results = {"success": None, "msg": None, "return": None}

        if isinstance(location, int):
            results = self._get_rest_call('%s/locations/%s' % (self.foreman, location))
            if 'error' in results:
                #-- This is not likely to execute, as if the host ID is not
                #   found a 404 is thrown, which is caught by the exception
                #   handling mechanism, and the program will bomb out.
                #   Not sure I want to change that...
                self.results['success'] = False
                self.results['msg'] = 'Warning: No Location ID %s.' % location
                self.results['return'] = results
            else:
                self.results['success'] = True
                self.results['msg'] = 'Success: Location ID %s found.' % location
                self.results['return'] = results
        else:
            if '/' in location:
                search_str = 'title~"%s"' % location
            else:
                search_str = 'name~"%s"' % location

            results = self._get_rest_call('%s/locations/' % (self.foreman),
                                          urlencode([('search', '' + str(search_str))]))
            if results['subtotal'] == 0:
                self.results['success'] = False
                self.results['msg'] = 'Warning: No location matches for %s.' % location
                self.results['return'] = results['results']
            elif results['subtotal'] > 1:
                self.results['success'] = False
                self.results['msg'] = 'Warning: Too many location matches for %s (%s).' % (location, results['total'])
                self.results['return'] = results['results']
            else:
                self.results['success'] = True
                self.results['msg'] = 'Success: Location %s found.' % location
                self.results['return'] = results['results'][0]

        logger.debug(self.results['msg'])
        if self.results['success']:
            return self.results['return']
        return None

    def get_loc_list(self):
        ''' This returns a list of Satellite 6 locations.

        Returns:
            List of Orgs (dict). Of particular value will be

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        item = 0
        page_item = 0
        page = 1

        results = self._get_rest_call('%s/locations' % (self.foreman),
                                      {'page': page, 'per_page': self.per_page})
        while item < results['subtotal']:
            if page_item == self.per_page:
                page += 1
                page_item = 0
                results = self._get_rest_call('%s/locations' % (self.foreman),
                                              {'page': page, 'per_page': self.per_page})
            yield results['results'][page_item]
            item += 1
            page_item += 1

    def set_host_lce(self, host, lce):
        ''' Set the LifeCycle Environment of a Sat6 host

         Args:
            host:           Host to change
            lce:            New LCE to set

        Returns:
            Status of request. Will set self.results

       '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        self.results = {"success": None, "msg": None, "return": None}
        if host is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed host is None.'
        elif 'id' not in host:
            logger.debug('Host does not have ID attribute, attempting lookup for: %s.', host)
            host = self.get_host(host)
        #-- We rely on the fact that get_host will set self.results appropriately
        if self.results['success'] is False:
            logger.debug(self.results['msg'])
            return False

        if lce is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed LCE is None.'
        #-- We rely on the fact that get_org_lce will set self.results appropriately
        elif 'id' not in lce:
            logger.debug('LCE does not have ID attribute, attempting lookup for: %s.', lce)
            lce = self.get_org_lce(self.lookup_lce_name(lce))
        if self.results['success'] is False:
            logger.debug(self.results['msg'])
            return False

        if 'content_facet_attributes' not in host:
            self.results['success'] = False
            self.results['msg'] = '%s is not a content host.' % (host['name'])
            return False

        if host['content_facet_attributes']['lifecycle_environment']['id'] == lce['id']:
            self.results['return'] = host
            self.results['success'] = True
            self.results['msg'] = 'LCE was already %s, no change needed.' % (lce['name'])
            return True

        results = self._put_rest_call('%s/hosts/%s' % (self.foreman, host['id']),
                                      {'host': {'content_facet_attributes':
                                                    {'lifecycle_environment_id': lce['id']}
                                               }}
                                     )
        if results['content_facet_attributes']['lifecycle_environment']['id'] == lce['id']:
            self.results['return'] = results
            self.results['success'] = True
            self.results['msg'] = 'LCE changed to %s.' % (lce['name'])
            return True

        self.results['return'] = results
        self.results['success'] = False
        self.results['msg'] = 'LCE not set, cause unknown.'
        return False

    def set_host_loc(self, host, location):
        ''' Set the LifeCycle Environment of a Sat6 host

         Args:
            host:           Host to change
            location:            New Location to set

        Returns:
            Status of request. Will set self.results

       '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        self.results = {"success": None, "msg": None, "return": None}
        if host is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed host is None.'
        elif 'id' not in host:
            logger.debug('Host does not have ID attribute, attempting lookup for: %s.', host)
            host = self.get_host(host)
        #-- We rely on the fact that get_host will set self.results appropriately
        if self.results['success'] is False:
            logger.debug(self.results['msg'])
            return False

        if location is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed Location is None.'
        #-- We rely on the fact that get_org_location will set self.results appropriately
        elif 'id' not in location:
            logger.debug('Location does not have ID attribute, attempting lookup for: %s.', location)
            location = self.get_loc(location)
        if self.results['success'] is False:
            logger.debug(self.results['msg'])
            return False

        if host['location_id'] == location['id']:
            self.results['return'] = host
            self.results['success'] = True
            self.results['msg'] = 'Location was already %s, no change needed.' % (location['name'])
            return True

        results = self._put_rest_call('%s/hosts/%s' % (self.foreman, host['id']),
                                      {'host': {'location_id': location['id']} }
                                     )
        if results['location_id'] == location['id']:
            self.results['return'] = results
            self.results['success'] = True
            self.results['msg'] = 'Location changed to %s.' % (location['title'])
            return True

        self.results['return'] = results
        self.results['success'] = False
        self.results['msg'] = 'Location not set, cause unknown.'
        return False

    def add_host_hc(self, host, collection):
        ''' Add a Sat6 host to a collection

         Args:
            host:           Host to add
            collection:     New collection to add to

        Returns:
            Status of request. Will set self.results

       '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        self.results = {"success": None, "msg": None, "return": None}
        if host is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed host is None.'
        elif 'id' not in host:
            logger.debug('Host does not have ID attribute, attempting lookup for: %s.', host)
            host = self.get_host(host)
        #-- We rely on the fact that get_host will set self.results appropriately
        if self.results['success'] is False:
            logger.debug(self.results['msg'])
            return False

        if collection is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed Collection is None.'
        #-- We rely on the fact that get_org_location will set self.results appropriately
        elif 'id' not in collection:
            logger.debug('Collection does not have ID attribute, attempting lookup for: %s.', collection)
            collection = self.get_hc(collection)
        if self.results['success'] is False:
            logger.debug(self.results['msg'])
            return False

        for _, item in enumerate(host['host_collections']):
            if item['id'] == collection['id']:
                self.results['return'] = host
                self.results['success'] = True
                self.results['msg'] = 'Host already in %s, no change needed.' % (collection['name'])
                return True

        results = self._put_rest_call('%s/host_collections/%s/add_hosts' % (self.katello, collection['id']),
                                      {'id': collection['id'], 'host_ids': host['id']}
                                     )
        host = self.get_host(host['id'])
        for _, item in enumerate(host['host_collections']):
            if item['id'] == collection['id']:
                self.results['return'] = host
                self.results['success'] = True
                self.results['msg'] = 'Host successfully added to %s.' % (collection['name'])
                return True
        self.results['return'] = results
        self.results['success'] = False
        self.results['msg'] = 'Host  not added to collection, cause unknown.'
        return False

    def remove_host_hc(self, host, collection):
        ''' Remove a Sat6 host to a collection

         Args:
            host:           Host to remove
            collection:     New collection to remove from

        Returns:
            Status of request. Will set self.results

       '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        self.results = {"success": None, "msg": None, "return": None}
        if host is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed host is None.'
        elif 'id' not in host:
            logger.debug('Host does not have ID attribute, attempting lookup for: %s.', host)
            host = self.get_host(host)
        #-- We rely on the fact that get_host will set self.results appropriately
        if self.results['success'] is False:
            logger.debug(self.results['msg'])
            return False

        if collection is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed Collection is None.'
        #-- We rely on the fact that get_org_location will set self.results appropriately
        elif 'id' not in collection:
            logger.debug('Collection does not have ID attribute, attempting lookup for: %s.', collection)
            collection = self.get_hc(collection)
        if self.results['success'] is False:
            logger.debug(self.results['msg'])
            return False

        in_list = False
        for _, item in enumerate(host['host_collections']):
            if item['id'] == collection['id']:
                in_list = True

        if not in_list:
            self.results['return'] = host
            self.results['success'] = True
            self.results['msg'] = 'Host not in %s, no change needed.' % (collection['name'])
            return True

        results = self._put_rest_call('%s/host_collections/%s/remove_hosts' % (self.katello, collection['id']),
                                      {'id': collection['id'], 'host_ids': host['id']}
                                     )
        host = self.get_host(host['id'])
        for _, item in enumerate(host['host_collections']):
            if item['id'] == collection['id']:
                self.results['return'] = results
                self.results['success'] = False
                self.results['msg'] = 'Host not removed from collection, cause unknown.'
                return True
        self.results['return'] = host
        self.results['success'] = True
        self.results['msg'] = 'Host successfully removed from collection %s.' % (collection['name'])
        return False


#==============================================================================
def main():
    ''' This is where the action takes place
        We expect options and logger to be global
    '''
    logger.debug('Starting main()')
    #-- TODO: Do something more interesting here...


#==============================================================================
if __name__ == '__main__':
    #-- Setting up logger here so we can use them in even of exceptions.
    #   Parsing options here as we need them to setup the logger.
    options = RunOptions(sys.argv[1:])           #: pylint: disable=invalid-name
    logger = RunLogger(options.debug)            #: pylint: disable=invalid-name
    if __require_root__ and os.getegid() != 0:
        logger.error('Must be run as root.')
        sys.exit(77)

    #-- NOTE: "except Exception as variable:" syntax was added in 2.6, previously
    #         one would use "except Exception, variable:", but that is not
    #         compatible with 3.x. In order to be compatible with 2.5 (for RHEL 5)
    #         and forward, we use "execpt Exception:", then on the first line of
    #         the exception use "_, error, _ = sys.exc_info()". HOWEVER, pylint
    #         will no longer be able to warn on object members...
    #         type, value, traceback = sys.exc_info()
    try:
        main()
    except KeyboardInterrupt: # Catches Ctrl-C
        logger.debug('Caught Ctrl-C')
        EXIT_STATUS = 130
    except SystemExit as error: # Catches sys.exit()
        #_, error, _ = sys.exc_info()
        logger.debug('Caught SystemExit')
        logger.warning('%s: [SystemExit] %s', __basename__, error)
    except IOError as error:
        #_, error, _ = sys.exc_info()
        logger.debug('Caught IOError')
        if error.errno is None:
            logger.critical('%s: [IOError]: %s', __basename__, error)
            EXIT_STATUS = 10
        elif error.errno == 2:                #: No such file/directory
            logger.critical('%s: [IOError] %s: %s', __basename__,
                            error, error.filename
                           )
            EXIT_STATUS = os.EX_UNAVAILABLE
        elif error.errno == 13:                #: Permission Denied
            logger.critical('%s: [IOError] %s: %s', __basename__,
                            error, error.filename
                           )
            EXIT_STATUS = os.EX_NOPERM
        else:
            logger.critical('%s: [IOError] %s', __basename__, error)
            EXIT_STATUS = error.errno
    except OSError as error:
        #_, error, _ = sys.exc_info()
        logger.debug('Caught OSError')
        if error.errno == 2:                #: No such file/directory
            logger.critical('%s: [OSError] %s: %s', __basename__,
                            error, error.filename
                           )
            EXIT_STATUS = os.EX_UNAVAILABLE
        else:
            logger.critical('%s: [OSError] %s', __basename__, error)
            EXIT_STATUS = error.errno
    except Exception as error:                   #: pylint: disable=broad-except
        #_, error, _ = sys.exc_info()
        logger.debug('Caught Exception: %s', sys.exc_info())
        logger.critical('%s: %s', __basename__, error)
        EXIT_STATUS = 10
    else:
        logger.debug('main() exited cleanly.')
        if EXIT_STATUS is None:
            EXIT_STATUS = os.EX_OK
    #-- NOTE: "try..except..finally" does not work pre 2.5
    finally:
        logger.debug('Mandatory clean-up.')
        if EXIT_STATUS is None:
            logger.debug('EXIT_STATUS is still None.')
            EXIT_STATUS = 20
        if options.debug:
            print('\n------ end ------\n')
        logging.shutdown()
        sys.exit(EXIT_STATUS)
    #-- NOTE: more exit codes here:
    #--   https://docs.python.org/2/library/os.html#process-management
