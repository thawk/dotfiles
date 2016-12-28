#!/usr/bin/env python2
# vim: set fileencoding=utf-8 tabstop=4 expandtab shiftwidth=4 softtabstop=4:

# Imports
import argparse
import codecs
import locale
import logging
import sys
import subprocess
import json
import pandas as pd
import numpy as np

VERSION = u'20161128'
TIME_ZONE = 'Asia/Shanghai'

def timewarrior_summary(options):
    output = subprocess.check_output(['timew', 'export'] + options).decode(locale.getpreferredencoding())
    return json.loads(output)

def main(**kwargs):
    l = timewarrior_summary(kwargs['options'])
    for t in l:
        t['tags'] = u','.join(t['tags'])

    tracked = pd.DataFrame(l)

    tracked['start'] = pd.to_datetime(tracked['start']).dt.tz_localize('UTC').dt.tz_convert(TIME_ZONE)
    tracked['date'] = tracked['start'].dt.date
    tracked['end'] = pd.to_datetime(tracked['end']).dt.tz_localize('UTC').dt.tz_convert(TIME_ZONE)
    tracked['duration'] = ((tracked['end'] - tracked['start']) / pd.Timedelta('1h')).apply(lambda v: np.ceil(v * 100)/100)
    pt = tracked.pivot_table('duration', columns='date', index=['tags'], aggfunc=np.sum, margins=True)
    print pt.fillna('-').to_csv(sep='\t', float_format='%.2f')

if __name__ == '__main__':
    reload(sys)
    sys.stdout = codecs.getwriter(locale.getpreferredencoding())(sys.stdout)
    sys.stderr = codecs.getwriter(locale.getpreferredencoding())(sys.stderr)
    sys.setdefaultencoding(locale.getpreferredencoding())

    parser = argparse.ArgumentParser(
        description=u'''\
description''')

    parser.add_argument('-v', '--verbose', action='store_true', dest='verbose', default=False, help=u'Be moderatery verbose')
    parser.add_argument('-q', '--quiet',  action='store_true', dest='quiet', default=False, help=u'Only show warning and errors')
    parser.add_argument('--version',  action='version', version=VERSION, help=u'Show version and quit')
    parser.add_argument('options', nargs='*', help=u'timewarrior options')

    args = parser.parse_args()

    # 对解释出来的参数进行编码转换
    for k in vars(args):
        if isinstance(getattr(args, k), str):
            setattr(args, k, unicode(getattr(args, k), locale.getpreferredencoding()).strip())

    # 日志初始化
    log_format = u'%(asctime)s %(levelname)s %(message)s'

    if args.quiet:
        logging.basicConfig(level=logging.WARNING, format=log_format)
    elif args.verbose:
        logging.basicConfig(level=logging.DEBUG, format=log_format)
    else:
        logging.basicConfig(level=logging.INFO, format=log_format)

    main(**vars(args))
