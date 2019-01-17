#!/usr/bin/python2 -tt
# pylint: disable=too-many-lines
# Yes, this is far too long, someday will turn it into a library...
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

    :synopsis: A single-file tool for interacting with Sat6

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
import pwd
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
#==============================================================================
#-- Variables which are meta for the script should be dunders (__varname__)
__version__ = '3.2.1' #: current version
__revised__ = '20190117-134926' #: date of most recent revision
__contact__ = 'awmyhr <awmyhr@gmail.com>' #: primary contact for support/?'s
__synopsis__ = 'Light-weight, host-centric alternative to hammer'
__description__ = '''Allows the user to perform a variety of tasks on a
Satellite 6 server from any command line without hammer.

Currently available tasks, [aliases] and (relevant actions) are:
 - host-collection       [hc]  (get, add, remove, info, list, search)
 - content-view          [cv]  (get, set, info, list, search)
 - erratum               [err] (get, info, list, search)
 - host                  [h]   (get, info, list, search)
 - lifecycle-environment [lce] (get, set, info, list)
 - location              [loc] (get, set, info, list)
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
    new_logger.debug('Logname:   %s', pwd.getpwuid(os.geteuid())[0])
    new_logger.debug('[re]uid:  %s/%s', os.getuid(), os.geteuid())
    new_logger.debug('PID/PPID:  %s/%s', os.getpid(), os.getppid())
    if options._options is not None:             #: pylint: disable=protected-access
        new_logger.debug('Parsed Options: %s', options._options) #: pylint: disable=protected-access
    if debug:
        print('\n----- start -----\n')

    return new_logger


#==============================================================================
class RunOptions(object):
    ''' Parse the options and put them into an object

        Returns:
            A RunOptions object.

    '''
    _defaults = {
        'authkey': None,
        'create': False,
        'debug': False,
        'id': None,
        'insecure': 0,
        'name': None,
        'password': None,
        'hostname': None,
        'username': None
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
            raise ValueError('Options already initialized.')
        else:
            (self._options, self._arguments) = self._parse_args(args)

    def _load_configs(self):
        parser = ConfigParser.SafeConfigParser(defaults=self._defaults)
        parser.read(['/etc/rhsm/rhsm.conf',
                     os.path.expanduser('~/.satellite6'),
                     os.path.expanduser('~/.%s' % __cononical_name__),
                     '%s.cfg' % __cononical_name__])
        #-- TODO: Define possible sections
        if not parser.has_section('debug'):
            parser.add_section('debug')
        if not parser.has_section('organization'):
            parser.add_section('organization')
        if not parser.has_section('server'):
            parser.add_section('server')
        if not parser.has_section('user'):
            parser.add_section('user')
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

    @property
    def authkey(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.authkey
        return None

    @property
    def create(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.create
        return self._defaults['create']

    @property
    def configfile(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.configfile
        return None

    @property
    def hostlist(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.hostlist
        return None

    @property
    def hostname(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.hostname
        return None

    @property
    def insecure(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.insecure
        return None

    @property
    def lifecycle(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.lifecycle
        return None

    @property
    def org_id(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.org_id
        return None

    @property
    def org_name(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.org_name
        return None

    @property
    def password(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.password
        return None

    @property
    def server(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.server
        return None

    @property
    def username(self):
        ''' Class property '''
        if self._options is not None:
            return self._options.username
        return None

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
        usage_string = ('%s [options] <task> get <hostname>\n'
                        '  or:  %s [options] <task> <add|remove|set> <hostname> <target>\n'
                        '  or:  %s [options] <task> info <target>\n'
                        '  or:  %s [options] <task> search <string>\n'
                        '  or:  %s [options] <task> list') % (
                            __basename__, __basename__, __basename__, __basename__, __basename__)
        version_string = '%s (%s) %s' % (__cononical_name__, __project_name__, __version__)
        if __gnu_version__:
            version_string += '\nCopyright %s\nLicense %s\n' % (__copyright__, __license__)
        parser = _ModOptionParser(version=version_string, usage=usage_string,
                                  description=description_string, epilog=epilog_string)
        self.parser = parser
        #-- TODO: Add options, also set _default and @property (if needed).
        #-- Visible Options
        #   These can *not* be set in a config file
        parser.add_option('-c', '--config', dest='configfile', type='string',
                          help='User Satellite config file.', default=None)
        parser.add_option('--create', dest='create', action='store_true',
                          help='Create target (if needed).', default=False)
        #   These could be set in a config file
        parser.add_option('-o', '--organization', dest='org_name', type='string',
                          help='Organization name.',
                          default=self._configs.get('organization', 'name'))
        parser.add_option('-O', '--organization-id', dest='org_id', type='int',
                          help='Organization ID number.',
                          default=self._configs.get('organization', 'id'))
        parser.add_option('-s', '--server', dest='server', type='string',
                          help='Satellite server.',
                          default=self._configs.get('server', 'hostname'))
        parser.add_option('-u', '--username', dest='username', type='string',
                          help='Satellite username.',
                          default=self._configs.get('user', 'username'))
        parser.add_option('-p', '--password', dest='password', type='string',
                          help='Satellite user password.',
                          default=self._configs.get('user', 'password'))
        parser.add_option('-K', '--userkey', dest='authkey', type='string',
                          help='Satellite user access key.',
                          default=self._configs.get('user', 'authkey'))

        #-- Hidden Options
        #   These can *not* be set in a config file
        parser.add_option('--help-rest', dest='helprest', action='store_true',
                          help=optparse.SUPPRESS_HELP, default=None)
        #   These could be set in a config file
        parser.add_option('--ssl-insecure', dest='insecure', action='store_true',
                          help=optparse.SUPPRESS_HELP,
                          default=self._configs.get('server', 'insecure'))
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
        if parsed_opts.org_id and parsed_opts.org_name:
            parser.error('Provide either Organization ID or Name (or neither), not both.')

        if len(parsed_args) < 1:
            parser.error('Not enough arguments.')
        elif len(parsed_args) > 4:
            parser.error('Too many arguments.')

        if parsed_opts.authkey is None:
            if parsed_opts.username is None:
                try:
                    from six.moves import input
                    parsed_opts.username = input('Username for Satellite server: ')
                except ImportError:
                    raise ImportError('The input module is required.')
            if parsed_opts.password is None:
                try:
                    import getpass
                    parsed_opts.password = getpass.getpass('Password for Satellite server: ')
                except ImportError:
                    raise ImportError('The getpass module is required.')

        return parsed_opts, parsed_args


#==============================================================================
class UtilityClass(object):
    ''' Class for interacting with Satellite 6 API '''
    __version = '1.1.0'

    per_page = 100

    def __init__(self, server=None, username=None, password=None,
                 authkey=None, insecure=False, token=None, client_id=None,
                 cookiefile=None):
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        logger.debug('Initiallizing UtilityClass version %s.', self.__version)
        logger.debug(locals())
        if token is not None:
            authorization = 'Bearer %s' % token['access_token']
        else:
            if authkey is None:
                if username is None or password is None:
                    raise RuntimeError('Must provide either authkey or username/password pair.')
                username = username
                authkey = base64.b64encode('%s:%s' % (username, password)).strip()
                logger.debug('Created authkey for %s: %s' % (username, authkey))
            else:
                authkey = authkey
            authorization = 'Basic %s' % authkey
        self.connection = requests.Session()
        self.connection.headers = {
            'x-ibm-client-id': client_id,
            'content-type': 'application/json',
            'authorization': authorization,
            'accept': 'application/json',
            'cache-control': 'no-cache'
        }
        logger.debug('Headers set: %s', self.connection.headers)
        self.connection.verify = not bool(insecure)
        self.cookiefile = cookiefile
        if cookiefile is not None:
            self.connection.cookies = LWPCookieJar(cookiefile)
            try:
                self.connection.cookies.load(ignore_discard=True)
            except IOError:
                pass
        self.verbose = False
        self.results = {"success": None, "msg": None, "return": None}

    def __del__(self):
        if self.cookiefile is not None:
            try:
                self.connection.cookies.save(ignore_discard=True)
            except IOError:
                pass

    #===============================================================================
    #-- The following originates from a  StackOverflow thread titled
    #   "Check if a string matches an IP address pattern in Python".
    #   We are only interested in valid IPv4 addresses.
    #===============================================================================
    # https://stackoverflow.com/questions/3462784/check-if-a-string-matches-an-ip-address-pattern-in-python
    #===============================================================================
    @classmethod
    def is_valid_ipv4(cls, ipaddr):
        '''Checks if passed paramater is a valid IPv4 address'''
        parts = ipaddr.split('.')
        if len(parts) != 4:
            return False
        try:
            return all(0 <= int(p) < 256 for p in parts)
        except ValueError:
            return False

    # def _get_cookies(self):
    #     ''' Handle session cookie '''
    #     logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    #     self.cookies = LWPCookieJar(os.getenv("HOME") + "/.sat6_api_session")
    #     try:
    #         self.cookies.load(ignore_discard=True)
    #     except IOError:
    #         pass
    #     return self.cookies

    def rest_call(self, method, url, params=None, data=None, jsonin=None):
        ''' Call a REST API URL using method.

        Args:
            session_obj (obj): Session object
            method (str):      One of: get, put, post
            url (str):         URL of API
            params (dict):     Dict of params to pass to Requests.get

        Returns:
            Results of API call in a dict

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        results = {"success": None, "msg": None, "return": None}

        logger.debug('Calling URL: %s', url)
        logger.debug('Using method: %s', method)
        logger.debug('With Headers: %s', self.connection.headers)
        if params is not None:
            logger.debug('With params: %s', params)
        if jsonin is not None:
            logger.debug('With json: %s', jsonin)
        if data is not None:
            logger.debug('With data: %s', data)
            data = json.dumps(data)

        try:
            req_results = self.connection.request(method, url, params=params, data=data, json=jsonin)
            logger.debug('Final URL: %s', req_results.url)
            logger.debug('Return Headers: %s', req_results.headers)
            logger.debug('Status Code: %s', req_results.status_code)
            logger.debug('Results: %s', req_results.content)
            rjson = req_results.json()
            if not req_results.ok:
                if self.verbose:
                    logger.debug('Results: %s', rjson)
                if 'error' in rjson:
                    logger.debug('Requests API call returned error.')
                    if 'full_messages' in rjson['error']:
                        logger.error('\n'.join(rjson['error']['full_messages']))
                    else:
                        logger.error('Sorry, no further info, try --debug.')
                elif 'displayMessage' in rjson:
                    logger.debug(rjson['displayMessage'])
                    logger.error('Sorry, no useful info, try --debug.')
                else:
                    logger.error('Sorry, no error info, try --debug.')
            req_results.raise_for_status()
            results['success'] = True
            results['return'] = rjson
        except requests.exceptions.HTTPError as error:
            logger.debug('Caught Requests HTTP Error.')
            results['msg'] = '[HTTPError]: %s' % (error.message) #: pylint: disable=no-member
        except requests.exceptions.ConnectionError as error:
            logger.debug('Caught Requests Connection Error.')
            results['msg'] = '[ConnectionError]: %s' % (error.message) #: pylint: disable=no-member
        except requests.exceptions.Timeout as error:
            logger.debug('Caught Requests Timeout.')
            results['msg'] = '[Timeout]: %s' % (error.message) #: pylint: disable=no-member
        except requests.exceptions.RequestException as error:
            logger.debug('Caught Requests Exception.')
            results['msg'] = '[Requests]: REST call failed: %s' % (error.message) #: pylint: disable=no-member

        logger.debug('rest_call: %s', results['msg'])
        return results

    def find_item(self, url, search=None, field='name'):
        ''' Searches for and returns info for a Satellite 6 host.

        Args:
            hostname (str):        Name of host to find.

        Returns:

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        results = {"success": False, "msg": None, "return": None}

        if url is None:
            results['msg'] = 'Error: No url passed.'
        else:
            search_str = '%s~"%s"' % (field, search)

            results = self.rest_call('get', url,
                                      urlencode([('search', '' + str(search_str))]))
            if results['return']['subtotal'] == 0:
                results['success'] = False
                results['msg'] = 'Warning: No matches for %s.' % search
            elif results['return']['subtotal'] > 1:
                results['success'] = False
                results['msg'] = 'Warning: Too many matches for %s (%s).' % (search, results['total'])
            else:
                results['success'] = True
                results['msg'] = 'Success: %s found.' % search
                results['return'] = results['return']['results'][0]

        logger.debug('find_item: %s', results['msg'])
        return results

    def get_item(self, url, label):
        ''' Searches for and returns info for a Satellite 6 host.

        Args:
            url (str):        url to hit.

        Returns:

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        results = {"success": False, "msg": None, "return": None}

        if url is None:
            results['msg'] = 'Error: No url passed.'
        else:
            results = self.rest_call('get', url)
            if 'error' in results['return']:
                #-- This is not likely to execute, as if the host ID is not
                #   found a 404 is thrown, which is caught by the exception
                #   handling mechanism, and the program will bomb out.
                #   Not sure I want to change that...
                results['success'] = False
                results['msg'] = 'Warning: %s not found.' % label
            else:
                results['success'] = True
                results['msg'] = 'Success: %s found.' % label

        logger.debug('get_item: %s', results['msg'])
        return results

    def get_list(self, url, search=None, field='name', per_page=None):
        ''' This returns a list of Satellite 6 Hosts.

        Returns:
            List of Hosts (dict). Of particular value will be

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        if per_page is None:
            per_page = self.per_page
        if search is None:
            params = {'page': 1, 'per_page': per_page}
        else:
            if '=' in search:
                field, search = search.split('=')
            params = {'page': 1, 'per_page': per_page,
                      'search': '%s~"%s"' % (field, search)}
        item = 0
        page_item = 0

        results = self.rest_call('get', url, params)
        while item < results['return']['subtotal']:
            if page_item == per_page:
                params['page'] += 1
                page_item = 0
                results = self.rest_call('get', url, params)
            yield results['return']['results'][page_item]
            item += 1
            page_item += 1


#==============================================================================
class Sat6Object(object):
    ''' Class for interacting with Satellite 6 API '''
    __version = '2.1.0'
    #-- Max number of items returned per page.
    #   Though we allow this to be configured, KB articles say 100 is the
    #   optimal value to avoid timeouts.
    per_page = 100
    lookup_tables = {'lce': 'lut/lce_name.json'}
    hl_start = '\x1b[38;2;100;149;237m'
    hl_end = '\x1b[0m'

    def __init__(self, server=None, username=None, password=None,
                 authkey=None, org_id=None, org_name=None, insecure=False):
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        logger.debug('Initiallizing Sat6Object version %s.', self.__version)
        if server is None:
            raise RuntimeError('Must provide Satellite server name.')
        self.server = server
        self.url = 'https://%s' % server
        self.pub = '%s/pub' % self.url
        self.foreman = '%s/api/v2' % self.url
        self.katello = '%s/katello/api' % self.url
        self.util = UtilityClass(username=username, password=password,
                                 authkey=authkey, insecure=insecure,
                                 cookiefile=os.getenv("HOME") + "/.sat6_api_session")
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
            results = self.util.rest_call('get', '%s/%s' % (self.pub,
                                          self.lookup_tables['lce']))
            if results['success']:
                self.lutables['lce'] = results['return']
                if '_revision' in self.lutables['lce']:
                    logger.debug('LCE Table revision: %s', self.lutables['lce']['_revision'])
                else:
                    logger.debug('Warning: LCE Table did not have _revision tag.')
            else:
                self.lutables['lce'] = None
        if self.lutables['lce']:
            return self.lutables['lce'].get(lce_tag.lower(), None)
        return None

    def get_host(self, hostname=None):
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
        self.results = {"success": False, "msg": None, "return": None}

        if hostname is None:
            self.results['msg'] = 'Error: Hostname passed was type None.'
        else:
            logger.debug('Looking for host: %s', hostname)

            if not isinstance(hostname, int):
                if not self.util.is_valid_ipv4(hostname):
                    hostname = hostname.split('.')[0]
                self.results = self.util.find_item('%s/hosts' % (self.foreman), hostname)
                if self.results['success']:
                    hostname = self.results['return']['id']
                else:
                    logger.debug('find unsuccessful: %s' % self.results)
                    hostname = None
            if hostname is not None:
                self.results = self.util.get_item('%s/hosts/%s' % (self.foreman, hostname), 'host_id %s' % hostname)

        logger.debug('get_host: %s', self.results['msg'])
        if self.results['success']:
            return self.results['return']
        return None

    def get_host_list(self, search=None, field='name'):
        ''' This returns a list of Satellite 6 Hosts.

        Returns:
            List of Hosts (dict). Of particular value will be

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access

        return self.util.get_list('%s/hosts' % (self.foreman), search=search, field=field)

    def get_cv(self, cview=None):
        ''' Returns info about a Satellite 6 content view.
            If content view is an integer (i.e., self.org_id), will return
            detailed info about that specific org.
            Otherwise will run a search for string passed. If only one result
            is found, will return some very basic info about said org.

        Args:
            content view (str/int): Name of content view to find.

        Returns:
            Basic info of content view (dict). Of particular value may be
            return['name']
            return['id']
            return['title']
            return['label']
            return['description']

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        self.results = {"success": False, "msg": None, "return": None}

        if cview is None:
            self.results['msg'] = 'Error: cview passed was type None.'
        else:
            logger.debug('Looking for cview: %s', cview)

            if not isinstance(cview, int):
                self.results = self.util.find_item('%s/content_views/' % (self.katello), cview)
                if self.results['success']:
                    cview = self.results['return']['id']
                else:
                    logger.debug('find unsuccessful: %s' % self.results)
                    cview = None
            if cview is not None:
                self.results = self.util.get_item('%s/content_views/%s' % (self.katello, cview), 'cview_id %s' % cview)

        logger.debug('get_cv: %s', self.results['msg'])
        if self.results['success']:
            return self.results['return']
        return None

    def get_cv_list(self, search=None, field='name'):
        ''' This returns a list of Satellite 6 content views.

        Returns:
            List of Content Views (dict). Of particular value will be

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access

        return self.util.get_list('%s/content_views' % (self.katello), search=search, field=field)

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
        self.results = {"success": False, "msg": None, "return": None}

        if collection is None:
            self.results['msg'] = 'Error: collection passed was type None.'
        else:
            logger.debug('Looking for collection: %s', collection)

            if not isinstance(collection, int):
                self.results = self.util.find_item('%s/organizations/%s/host_collections/' % (self.katello, self.org_id), collection)
                if self.results['success']:
                    collection = self.results['return']['id']
                else:
                    logger.debug('find unsuccessful: %s' % self.results)
                    collection = None
            if collection is not None:
                self.results = self.util.get_item('%s/host_collections/%s' % (self.katello, collection), 'collection_id %s' % collection)

        logger.debug('get_hc: %s', self.results['msg'])
        if self.results['success']:
            return self.results['return']
        return None

    def get_hc_list(self, search=None, field='name', org_id=None):
        ''' This returns a list of Satellite 6 content views.

        Returns:
            List of Host Collections (dict). Of particular value will be

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        if org_id is None:
            org_id = self.org_id

        return self.util.get_list('%s/organizations/%s/host_collections' % (self.katello, org_id), search=search, field=field)

    def create_hc(self, collection):
        ''' Creates a host collection in the default organization

        Args:
            collection (str): Name of collection to create

        Returns:
            Basic info of collection created
        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
        self.results = {"success": False, "msg": None, "return": None}

        if collection is None:
            self.results['msg'] = 'Error: Was not given collection to create.'
            return None
        logger.debug('Creating collection: %s', collection)

        check = self.get_hc(collection)
        if check:
            self.results['success'] = True
            self.results['msg'] = 'Collection %s exists, nothing to do.' % (collection)
            self.results['return'] = check
            return True

        self.results = self.util.rest_call('post', '%s/organizations/%s/host_collections' % (self.katello, self.org_id),
                                  data={'organization_id': self.org_id, 'name': collection}
                                 )
        if self.results['return']['id']:
            self.results['success'] = True
            self.results['msg'] = 'Collection %s created.' % (collection)
            return True
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
        self.results = {"success": False, "msg": None, "return": None}

        if organization is None:
            self.results['msg'] = 'Error: organization passed was type None.'
        else:
            logger.debug('Looking for organization: %s', organization)

            if not isinstance(organization, int):
                self.results = self.util.find_item('%s/organizations' % (self.katello), organization)
                if self.results['success']:
                    organization = self.results['return']['id']
                else:
                    logger.debug('find unsuccessful: %s' % self.results)
                    organization = None
            if organization is not None:
                self.results = self.util.get_item('%s/organizations/%s' % (self.katello, organization), 'org_id %s' % organization)

        logger.debug('get_org: ', self.results['msg'])
        if self.results['success']:
            return self.results['return']
        return None

    def get_org_list(self, search=None, field='name'):
        ''' This returns a list of Satellite 6 organizations.

        Returns:
            List of Orgs (dict). Of particular value will be

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access

        return self.util.get_list('%s/organizations' % (self.katello), search=search, field=field)

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
        self.results = {"success": False, "msg": None, "return": None}

        if lce_name is None:
            self.results['msg'] = 'Error: lce_name passed was type None.'
        else:
            logger.debug('Looking for Life Cycle Environment %s in org %s.', lce_name, org_id)

            if not isinstance(lce_name, int):
                self.results = self.util.find_item('%s/organizations/%s/environments' % (self.katello, org_id), lce_name)
                if self.results['success']:
                    lce_name = self.results['return']['id']
                else:
                    logger.debug('find unsuccessful: %s' % self.results)
                    lce_name = None
            if lce_name is not None:
                self.results = self.util.get_item('%s/organizations/%s/environments/%s' % (self.katello, org_id, lce_name), 'lce_id %s' % lce_name)

        logger.debug(self.results['msg'])
        if self.results['success']:
            return self.results['return']
        return None

    def get_org_lce_list(self, search=None, field='name', org_id=None):
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
        return self.util.get_list('%s/organizations/%s/environments' % (self.katello, org_id), search=search, field=field)

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
        self.results = {"success": False, "msg": None, "return": None}

        if location is None:
            self.results['msg'] = 'Error: location passed was type None.'
        else:
            logger.debug('Looking for location: %s', location)

            if not isinstance(location, int):
                if '/' in location:
                    field = 'title'
                else:
                    field = 'name'

                self.results = self.util.find_item('%s/locations/' % (self.foreman), location, field)
                if self.results['success']:
                    location = self.results['return']['id']
                else:
                    logger.debug('find unsuccessful: %s' % self.results)
                    location = None
            if location is not None:
                self.results = self.util.get_item('%s/locations/%s' % (self.foreman, location), 'loc_id %s' % location)

        logger.debug(self.results['msg'])
        if self.results['success']:
            return self.results['return']
        return None

    def get_loc_list(self, search=None, field='name'):
        ''' This returns a list of Satellite 6 locations.

        Returns:
            List of locations (dict). Of particular value will be

        '''
        logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access

        return self.util.get_list('%s/locations' % (self.foreman), search=search, field=field)

    def set_host_cv(self, host=None, cview=None):
        ''' Set the Content View of a Sat6 host

         Args:
            host:           Host to change
            cview:          New CView to set

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
            logger.debug('set_host_cv: %s', self.results['msg'])
            return False
        elif 'content_facet_attributes' not in host:
            self.results['success'] = False
            self.results['msg'] = '%s is not a content host.' % (host['name'])
            return False

        if cview is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed CView is None.'
        elif 'id' not in cview:
            logger.debug('CView does not have ID attribute, attempting lookup for: %s.', cview)
            cview = self.get_cv(cview)
        #-- We rely on the fact that get_cv will set self.results appropriately
        if self.results['success'] is False:
            logger.debug('set_host_cv: %s', self.results['msg'])
            return False

        if host['content_facet_attributes']['content_view']['id'] == cview['id']:
            self.results['success'] = True
            self.results['msg'] = 'CView was already %s, no change needed.' % (cview['name'])
            self.results['return'] = host
            logger.debug('set_host_cv: %s', self.results['msg'])
            return True

        self.results = self.util.rest_call('put', '%s/hosts/%s' % (self.foreman, host['id']),
                                      data={'host': {'content_facet_attributes':
                                                    {'content_view_id': cview['id']}
                                               }}
                                     )
        host = self.results['return']
        if host['content_facet_attributes']['content_view']['id'] == cview['id']:
            self.results['return'] = host
            self.results['success'] = True
            self.results['msg'] = 'CView changed to %s.' % (cview['name'])
            logger.debug('set_host_cv: %s', self.results['msg'])
            return True

        self.results['success'] = False
        self.results['msg'] = 'CView not set, cause unknown.'
        logger.debug('set_host_cv: %s', self.results['msg'])
        return False

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
            logger.debug('set_host_lce: %s', self.results['msg'])
            return False
        elif 'content_facet_attributes' not in host:
            self.results['success'] = False
            self.results['msg'] = '%s is not a content host.' % (host['name'])
            logger.debug('set_host_lce: %s', self.results['msg'])
            return False

        if lce is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed LCE is None.'
        #-- We rely on the fact that get_org_lce will set self.results appropriately
        elif 'id' not in lce:
            logger.debug('LCE does not have ID attribute, attempting lookup for: %s.', lce)
            lce = self.get_org_lce(self.lookup_lce_name(lce))
        if self.results['success'] is False:
            logger.debug('set_host_lce: %s', self.results['msg'])
            return False

        if host['content_facet_attributes']['lifecycle_environment']['id'] == lce['id']:
            self.results['success'] = True
            self.results['msg'] = 'LCE was already %s, no change needed.' % (lce['name'])
            self.results['return'] = host
            logger.debug('set_host_lce: %s', self.results['msg'])
            return True

        self.results = self.util.rest_call('put', '%s/hosts/%s' % (self.foreman, host['id']),
                                      data={'host': {'content_facet_attributes':
                                                    {'lifecycle_environment_id': lce['id']}
                                               }}
                                     )
        host = self.results['return']
        if host['content_facet_attributes']['lifecycle_environment']['id'] == lce['id']:
            self.results['success'] = True
            self.results['msg'] = 'LCE changed to %s.' % (lce['name'])
            self.results['return'] = host
            logger.debug('set_host_lce: %s', self.results['msg'])
            return True

        self.results['success'] = False
        self.results['msg'] = 'LCE not set, cause unknown.'
        logger.debug('set_host_lce: %s', self.results['msg'])
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
            logger.debug('set_host_loc: %s', self.results['msg'])
            return False

        if location is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed Location is None.'
        #-- We rely on the fact that get_org_location will set self.results appropriately
        elif 'id' not in location:
            logger.debug('Location does not have ID attribute, attempting lookup for: %s.', location)
            location = self.get_loc(location)
        if self.results['success'] is False:
            logger.debug('set_host_loc: %s', self.results['msg'])
            return False

        if host['location_id'] == location['id']:
            self.results['return'] = host
            self.results['success'] = True
            self.results['msg'] = 'Location was already %s, no change needed.' % (location['name'])
            logger.debug('set_host_loc: %s', self.results['msg'])
            return True

        self.results = self.util.rest_call('put', '%s/hosts/%s' % (self.foreman, host['id']),
                                  data={'host': {'location_id': location['id']} }
                                 )
        host = self.results['return']
        if host['location_id'] == location['id']:
            self.results['success'] = True
            self.results['msg'] = 'Location changed to %s.' % (location['title'])
            self.results['return'] = host
            logger.debug('set_host_loc: %s', self.results['msg'])
            return True

        self.results['success'] = False
        self.results['msg'] = 'Location not set, cause unknown.'
        logger.debug('set_host_loc: %s', self.results['msg'])
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
            logger.debug('add_host_hc: %s', self.results['msg'])
            return False

        if collection is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed Collection is None.'
        #-- We rely on the fact that get_org_location will set self.results appropriately
        elif 'id' not in collection:
            logger.debug('Collection does not have ID attribute, attempting lookup for: %s.', collection)
            collection = self.get_hc(collection)
        if self.results['success'] is False:
            logger.debug('add_host_hc: %s', self.results['msg'])
            return False

        for _, item in enumerate(host['host_collections']):
            if item['id'] == collection['id']:
                self.results['success'] = True
                self.results['msg'] = 'Host already in %s, no change needed.' % (collection['name'])
                self.results['return'] = host
                logger.debug('add_host_hc: %s', self.results['msg'])
                return True

        self.results = self.util.rest_call('put', '%s/host_collections/%s/add_hosts' % (self.katello, collection['id']),
                                  data={'id': collection['id'], 'host_ids': [host['id']]}
                                 )
        host = self.get_host(host['id'])
        for _, item in enumerate(host['host_collections']):
            if item['id'] == collection['id']:
                self.results['success'] = True
                self.results['msg'] = 'Host successfully added to %s.' % (collection['name'])
                self.results['return'] = host
                logger.debug('add_host_hc: %s', self.results['msg'])
                return True

        self.results['success'] = False
        self.results['msg'] = 'Host not added to collection, cause unknown.'
        logger.debug('add_host_hc: %s', self.results['msg'])
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
            logger.debug('remove_host_hc: %s', self.results['msg'])
            return False

        if collection is None:
            self.results['success'] = False
            self.results['msg'] = 'Passed Collection is None.'
        #-- We rely on the fact that get_org_location will set self.results appropriately
        elif 'id' not in collection:
            logger.debug('Collection does not have ID attribute, attempting lookup for: %s.', collection)
            collection = self.get_hc(collection)
        if self.results['success'] is False:
            logger.debug('remove_host_hc: %s', self.results['msg'])
            return False

        in_list = False
        for _, item in enumerate(host['host_collections']):
            if item['id'] == collection['id']:
                in_list = True

        if not in_list:
            self.results['return'] = host
            self.results['success'] = True
            self.results['msg'] = 'Host not in %s, no change needed.' % (collection['name'])
            logger.debug('remove_host_hc: %s', self.results['msg'])
            return True

        self.results = self.util.rest_call('put', '%s/host_collections/%s/remove_hosts' % (self.katello, collection['id']),
                                  data={'id': collection['id'], 'host_ids': [host['id']]}
                                 )
        host = self.get_host(host['id'])
        for _, item in enumerate(host['host_collections']):
            if item['id'] == collection['id']:
                self.results['success'] = False
                self.results['msg'] = 'Host not removed from collection, cause unknown.'
                logger.debug('remove_host_hc: %s', self.results['msg'])
                return False

        self.results['success'] = True
        self.results['msg'] = 'Host successfully removed from collection %s.' % (collection['name'])
        self.results['return'] = host
        logger.debug('remove_host_hc: %s', self.results['msg'])
        return True


#==============================================================================
def task_collection(sat6_session, verb, *args):
    ''' Manipulate host collections '''
    logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    if args:
        logger.debug('With verb: %s; and args: %s' % (verb, args))

    if verb == 'get':
        host = sat6_session.get_host(args[0])
        if host:
            if 'host_collections' in host:
                for hcollec in host['host_collections']:
                    print('%s' % hcollec['name'])
            else:
                raise RuntimeError('%s has no host collections' % host['name'])
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'add':
        new_hc = sat6_session.get_hc(args[1])
        if new_hc is None and options.create:
            logger.debug('collection does not exist, attempting to create.')
            if sat6_session.create_hc(args[1]):
                new_hc = sat6_session.get_hc(args[1])
            else:
                raise RuntimeError('Unable to create %s. %s' %
                                   (args[1], sat6_session.results['msg']))
        if new_hc is None:
            raise RuntimeError('"%s" does not exist in org %s.' %
                               (args[1], sat6_session.org_id))
        host = sat6_session.get_host(args[0])
        if host:
            if sat6_session.add_host_hc(host, args[1]):
                print('%s: %s' % (host['name'], sat6_session.results['msg']))
            else:
                raise RuntimeError('%s: %s', host['name'], sat6_session.results['msg'])
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'remove':
        new_hc = sat6_session.get_hc(args[1])
        if new_hc is None:
            raise RuntimeError('"%s" does not exist in org %s.' %
                               (args[1], sat6_session.org_id))
        host = sat6_session.get_host(args[0])
        if host:
            if sat6_session.remove_host_hc(host, args[1]):
                print('%s: %s' % (host['name'], sat6_session.results['msg']))
            else:
                raise RuntimeError('%s: %s', host['name'], sat6_session.results['msg'])
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'info':
        hcollec = sat6_session.get_hc(args[0])
        if hcollec:
            print(hcollec['name'])
        else:
            raise RuntimeError('"%s" not found.' % args[0])
    elif verb == 'list' or verb == 'search':
        if len(args) == 1:
            search = args[0]
            print('Search for: %s' % search)
        else:
            search = None
        print('%-35s: %s' % ('Name', 'Host count'))
        print('=' * 70)
        for hcollec in sat6_session.get_hc_list(search):
            print('%s%-35s: %s%s' % (sat6_session.hl_start,
                                     hcollec['name'],
                                     hcollec['total_hosts'],
                                     sat6_session.hl_end))
        print('=' * 70)
    else:
        options.parser.error('host-collection does not support action: %s' % verb)
    return True


#==============================================================================
def task_cview(sat6_session, verb, *args):
    ''' Manipulate Locations '''
    logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    if args:
        logger.debug('With verb: %s; and args: %s' % (verb, args))

    if verb == 'get':
        host = sat6_session.get_host(args[0])
        if host:
            if 'content_facet_attributes' in host:
                print(host['content_facet_attributes']['content_view_name'])
            else:
                print('%s is not a content host.' % host['name'])
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'set':
        new_cview = sat6_session.get_cv(args[1])
        if new_cview is None:
            raise RuntimeError('"%s" does not exist in org %s.' %
                               (args[1], sat6_session.org_id))
        host = sat6_session.get_host(args[0])
        if host:
            if sat6_session.set_host_cv(host, new_cview):
                print('%s: %s' % (host['name'], sat6_session.results['msg']))
            else:
                raise RuntimeError('%s: %s' % (host['name'], sat6_session.results['msg']))
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'info':
        cview = sat6_session.get_cv(args[0])
        if cview:
            print(cview['name'])
        else:
            raise RuntimeError('"%s" not found.' % args[0])
    elif verb == 'list' or verb == 'search':
        if len(args) == 1:
            search = args[0]
            print('Search for: %s' % search)
        else:
            search = None
        print('%-20s: %s' % ('Title', 'Description'))
        print('=' * 70)
        for cview in sat6_session.get_cv_list(search):
            print('%s%-20s: %s%s' % (sat6_session.hl_start,
                                     cview['name'], cview['description'],
                                     sat6_session.hl_end))
        print('=' * 70)
    else:
        options.parser.error('content-view does not support action: %s' % verb)
    return True


#==============================================================================
def task_errata(sat6_session, verb, *args):
    ''' Print host list '''
    logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    if args:
        logger.debug('With verb: %s; and args: %s' % (verb, args))

    if verb == 'get':
        host = sat6_session.get_host(args[0])
        if host:
            if 'errata_status_label' in host:
                print(host['errata_status_label'])
            else:
                print('Not a content host.')
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'info':
        host = sat6_session.get_host(args[0])
        if host:
            if 'content_facet_attributes' in host:
                print('Bugfix:      %5d' % host['content_facet_attributes']['errata_counts']['bugfix'])
                print('Enhancement: %5d' % host['content_facet_attributes']['errata_counts']['enhancement'])
                print('Security:    %5d' % host['content_facet_attributes']['errata_counts']['security'])
                print('Total:       %5d' % host['content_facet_attributes']['errata_counts']['total'])
            else:
                print('%s is not a content host.' % host['name'])
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'list' or verb == 'search':
        print('Retrieving host list. This could take quite some time...')
        if len(args) == 1:
            search = args[0]
            print('Search for: %s' % search)
        else:
            search = None
        print('%-35s: %5s %5s %5s %5s' % ('Name', 'Bug', 'Enhan', 'Sec', 'Total'))
        print('=' * 70)
        for host in sat6_session.get_host_list(search):
            if 'content_facet_attributes' in host:
                print('%s%-35s: %5d %5d %5d %5d%s' % (sat6_session.hl_start,
                                         host['name'],
                                         host['content_facet_attributes']['errata_counts']['bugfix'],
                                         host['content_facet_attributes']['errata_counts']['enhancement'],
                                         host['content_facet_attributes']['errata_counts']['security'],
                                         host['content_facet_attributes']['errata_counts']['total'],
                                         sat6_session.hl_end))
        print('=' * 70)
    else:
        options.parser.error('erratum does not support action: %s' % verb)
    return True


#==============================================================================
def task_host(sat6_session, verb, *args):
    ''' Print host list '''
    logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    if args:
        logger.debug('With verb: %s; and args: %s' % (verb, args))

    if verb == 'get':
        host = sat6_session.get_host(args[0])
        if host:
            print(host['subscription_status_label'])
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'info':
        host = sat6_session.get_host(args[0])
        if host:
            print(host['name'], end ="")
            if host['name'] != host['certname']:
                print("(%s)" % host['certname'], end ="")
            if host['ip'] is not None:
                print(" [%s]" % host['ip'], end ="")
            print()

            print('%s - %s' % (host['organization_name'],host['location_name']))
            if host['operatingsystem_name'] is not None:
                print('OS: %s' % host['operatingsystem_name'])
            if 'model_name' in host and host['model_name'] is not None:
                print('Model: %s' % host['model_name'])
            print('Status: %s' % host['subscription_status_label'])

            if len(host['subscription_facet_attributes']['virtual_guests']) > 0:
                print('Guests: ', end ="")
                for guest in host['subscription_facet_attributes']['virtual_guests']:
                    print(guest['name'], end =" ")
                print()
            if host['subscription_facet_attributes']['virtual_host'] is not None:
                print('Hypervisor: %s' % host['subscription_facet_attributes']['virtual_host']['name'])
            if 'content_facet_attributes' in host:
                print('CV:  %s' % host['content_facet_attributes']['content_view_name'])
                print('LCE: %s' % host['content_facet_attributes']['lifecycle_environment_name'])
                print('Errata needed: %s' % host['content_facet_attributes']['errata_counts']['total'])
            else:
                print('Not a content host.')
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'list' or verb == 'search':
        print('Retrieving host list. This could take quite some time...')
        if len(args) == 1:
            search = args[0]
            print('Search for: %s' % search)
        else:
            search = None
        print('%-35s: %s' % ('Name', 'Life-Cycle Environment'))
        print('=' * 70)
        for host in sat6_session.get_host_list(search):
            if 'content_facet_attributes' in host:
                print('%s%-35s: %s%s' % (sat6_session.hl_start,
                                         host['name'],
                                         host['content_facet_attributes']['lifecycle_environment']['name'],
                                         sat6_session.hl_end))
            else:
                print('%s%-35s: %s' %   (sat6_session.hl_start,
                                         host['name'],
                                         sat6_session.hl_end))
        print('=' * 70)
    else:
        options.parser.error('host does not support action: %s' % verb)
    return True


#==============================================================================
def task_lce(sat6_session, verb, *args):
    ''' Manipulate Life-Cycle Environments '''
    logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    if args:
        logger.debug('With verb: %s; and args: %s' % (verb, args))

    if verb == 'get':
        host = sat6_session.get_host(args[0])
        if host:
            if 'content_facet_attributes' in host:
                print('%s' % host['content_facet_attributes']['lifecycle_environment']['name'])
            else:
                print('%s is not a content host.' % host['name'])
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'set':
        new_lce = sat6_session.lookup_lce_name(args[1])
        if new_lce is None:
            raise RuntimeError('"%s" does not exist in org %s.' %
                               (args[1], sat6_session.org_id))
        host = sat6_session.get_host(args[0])
        if host:
            if sat6_session.set_host_lce(host, new_lce):
                print('%s: %s' % (host['name'], sat6_session.results['msg']))
            else:
                raise RuntimeError('%s: %s', host['name'], sat6_session.results['msg'])
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'info':
        lce = sat6_session.lookup_lce_name(args[0])
        if lce:
            print(lce)
        else:
            raise RuntimeError('"%s" not found.' % args[0])
    elif verb == 'list':
        _ = sat6_session.lookup_lce_name('qa')
        print('%-35s: %s' % ('Possible Values', 'Target LCE'))
        print('=' * 70)
        for key, value in sorted(sat6_session.lutables['lce'].iteritems(),
                                 key=(lambda (k, v): (v, k)) ):
            if not key.startswith('_'):
                print('%s%-35s: %s%s' % (sat6_session.hl_start,
                                         key, value,
                                         sat6_session.hl_end))
        print('=' * 70)
        print('Note: The values are case insensitive.')
    else:
        options.parser.error('lifecycle-environment does not support action: %s' % verb)
    return True


#==============================================================================
def task_location(sat6_session, verb, *args):
    ''' Manipulate Locations '''
    logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    if args:
        logger.debug('With verb: %s; and args: %s' % (verb, args))

    if verb == 'get':
        host = sat6_session.get_host(args[0])
        if host:
            if 'location_name' in host:
                print('%s' % host['location_name'])
            else:
                raise RuntimeError('%s has no location' % host['name'])
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'set':
        new_loc = sat6_session.get_loc(args[1])
        if new_loc is None:
            raise RuntimeError('"%s" does not exist in org %s.' %
                               (args[1], sat6_session.org_id))
        host = sat6_session.get_host(args[0])
        if host:
            if sat6_session.set_host_loc(host, new_loc):
                print('%s: %s' % (host['name'], sat6_session.results['msg']))
            else:
                raise RuntimeError('%s: %s' % (host['name'], sat6_session.results['msg']))
        else:
            raise RuntimeError('Host %s not found.' % args[0])
    elif verb == 'info':
        loc = sat6_session.get_loc(args[0])
        if loc:
            print(loc['title'])
        else:
            raise RuntimeError('"%s" not found.' % args[0])
    # elif verb == 'list' or verb == 'search':
    elif verb == 'list':
        if len(args) == 1:
            search = args[0]
            print('Search for: %s' % search)
        else:
            search = None
        print('%-35s: %s' % ('Title', 'Parent'))
        print('=' * 70)
        for loc in sat6_session.get_loc_list(search):
            if loc['parent_id'] is not None:
                parent = sat6_session.get_loc(loc['parent_id'])['title']
            else:
                parent = '[None]'
            print('%s%-35s: %s%s' % (sat6_session.hl_start,
                                     loc['title'], parent,
                                     sat6_session.hl_end))
        print('=' * 70)
    else:
        options.parser.error('location does not support action: %s' % verb)
    return True


#==============================================================================
def task__experiment(sat6_session, *args):
    ''' Playground for future features '''
    logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    if args:
        logger.debug('With args: %s' % args)

    print('%-35s: %s' % ('Name', 'Life-Cycle Environment'))
    print('=' * 70)
    for host in sat6_session.get_host_list(search='os_major=6'):
        if 'content_facet_attributes' in host:
            print('%s%-35s: %s%s' % (sat6_session.hl_start,
                                     host['name'],
                                     host['content_facet_attributes']['lifecycle_environment']['name'],
                                     sat6_session.hl_end))
        else:
            print('%s%-35s: %s' %   (sat6_session.hl_start,
                                     host['name'],
                                     sat6_session.hl_end))
    print('=' * 70)
    # my_hc = sat6_session.get_hc('et_dse_linux')
    # print(sat6_session.results)
    # print(my_hc['id'])

    # sat6_session.add_host_hc('lxrsvutilp03', 'et_dse_linux_test')
    # print(sat6_session.results['msg'])

    # sat6_session.remove_host_hc('lxrsvutilp03', 'et_dse_linux_test')
    # print(sat6_session.results['msg'])

    return True


#==============================================================================
def task__test(sat6_session, *args):
    ''' Runs a test suite '''
    logger.debug('Entering Function: %s', sys._getframe().f_code.co_name) #: pylint: disable=protected-access
    if args:
        logger.debug('With args: %s' % args)

    print('Content Views')
    for cview in sat6_session.get_cv_list():
        print("  ID: %3s  Name: %35s  Label: %s" % (cview['id'], cview['name'], cview['label']))
    print('-------------------')

    print('Host Collections')
    for hcollec in sat6_session.get_hc_list():
        print("  ID: %3s  Name: %35s  Hosts: %s" % (hcollec['id'], hcollec['name'], hcollec['total_hosts']))
    print('-------------------')

    print('Life-Cycle Environments')
    for lce in sat6_session.get_org_lce_list():
        print("  ID: %3s  Name: %35s  Title: %s" % (lce['id'], lce['name'], lce['label']))
    print('-------------------')

    print('Locations')
    for loc in sat6_session.get_loc_list():
        print("  ID: %3s  Name: %35s  Title: %s" % (loc['id'], loc['name'], loc['title']))
    print('-------------------')

    print('Organizations')
    for org in sat6_session.get_org_list():
        print("  ID: %3s  Name: %35s  Label: %s" % (org['id'], org['name'], org['label']))
    print('-------------------')

    return True


#==============================================================================
def main():
    ''' This is where the action takes place
        We expect options and logger to be global
    '''
    logger.debug('Starting main()')
    sat6_session = Sat6Object(server=options.server, username=options.username,
                              password=options.password, authkey=options.authkey,
                              org_id=options.org_id, org_name=options.org_name,
                              insecure=options.insecure)
    task = options.args[0]
    if len(options.args) >= 2:
        verb = options.args[1]
        if verb == 'ls':
            verb = 'list'
        elif verb == 'rm':
            verb = 'remove'

        if verb not in ['get', 'add', 'remove', 'set', 'info', 'list', 'search']:
            options.parser.error('Unknown action: %s' % verb)
        if verb == 'get' and len(options.args) != 3:
            options.parser.error('Action get requires only a hostname.')
        elif verb == 'add' and len(options.args) != 4:
            options.parser.error('Action add requires a hostname and target.')
        elif verb == 'remove' and len(options.args) != 4:
            options.parser.error('Action remove requires a hostname and target.')
        elif verb == 'set' and len(options.args) != 4:
            options.parser.error('Action set requires a hostname and target.')
        elif verb == 'info' and len(options.args) != 3:
            options.parser.error('Action info requires only a target.')
        elif verb == 'search' and len(options.args) != 3:
            options.parser.error('Action search requires only a string.')
        elif verb == 'list' and len(options.args) != 2:
            options.parser.error('Action list accepts no arguments.')
        logger.debug('Was asked to %s' % verb)
    else:
        verb = None

    if task == 'collection' or task == 'host-collection' or task == 'hc':
        task_collection(sat6_session, verb, *options.args[2:])
    elif task == 'cview' or task == 'content-view' or task == 'cv':
        task_cview(sat6_session, verb, *options.args[2:])
    elif task == 'errata' or task == 'erratum' or task == 'err':
        task_errata(sat6_session, verb, *options.args[2:])
    elif task == 'host' or task == 'h':
        task_host(sat6_session, verb, *options.args[2:])
    elif task == 'lifecycle' or task == 'lifecycle-environment' or task == 'lce':
        task_lce(sat6_session, verb, *options.args[2:])
    elif task == 'location' or task == 'loc':
        task_location(sat6_session, verb, *options.args[2:])
    elif task == '_experiment':
        task__experiment(sat6_session, *options.args[1:])
    elif task == '_test':
        task__test(sat6_session, *options.args[1:])
    else:
        options.parser.error('Unknown task: %s' % task)


#==============================================================================
if __name__ == '__main__':
    #-- Setting up logger here so we can use them in even of exceptions.
    #   Parsing options here as we need them to setup the logger.
    options = RunOptions(sys.argv[1:])           #: pylint: disable=invalid-name
    logger = RunLogger(options.debug)            #: pylint: disable=invalid-name
    if __require_root__ and os.getegid() != 0:
        logger.error('Must be run as root.')
        sys.exit(77)

    #-- This will disable insecure https warnings (amongst others)
    try:
        logging.captureWarnings(True)
    except AttributeError:
        logger.warn('Sorry, unable to suppress SSL warnings.')

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
