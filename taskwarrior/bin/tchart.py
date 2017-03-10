#!/usr/bin/env python

# Read task output and organise by day

import json
import commands
import argparse
import snack  # On Ubuntu do apt-get install python-newt to get snack module
from datetime import datetime, timedelta, date
from blessings import Terminal
from operator import itemgetter

class TaskReport(object):
    """
    This is the main class for this programme.
    """

    def __init__(self):

        self.weeks = 4  # Number of weeks to cover
        self.weekstart = date.today() - timedelta(date.weekday(date.today()))
        self.cutoffdate = self.weekstart + timedelta(weeks=self.weeks)
        self.construct_cmdline()
        self.load_tasks()

        self.run_report()

    def construct_cmdline(self):
        """
        Construct the Taskwarrior commandline to be used.
        """

        parser = argparse.ArgumentParser(description='Display tasks.')
        parser.add_argument("-f", "--filter", nargs='+',
                            help='a string specifying the task filter')
        args = parser.parse_args()

        self.consoleline = "rc.json.array=on "

        if args.filter:
            self.consoleline = self.consoleline + " ".join(args.filter)
            self.consoleline = (self.consoleline + ' status:pending') \
                if self.consoleline.find('status:pending') < 0 \
                else self.consoleline
            self.consoleline = (self.consoleline + ' export') \
                if self.consoleline.find('export') < 0 \
                else self.consoleline
            self.consoleline = 'task ' + self.consoleline
        else:
            # When no arguments are given.
            self.consoleline = 'task due.any: status:pending export'

        print self.consoleline
        print

    def load_tasks(self):
        """
        Load and sort the task list
        """
        tstring = commands.getoutput(self.consoleline)
        # tstring = '[' + tstring + ']'  # Adds brackets to comply with Json
        tasks = json.loads(tstring)

        # This section removes the tasks with no due dates and adds them to the
        # front of the list after it has been sorted

        due_list = []
        nodue_list = []
        for task in tasks:
            if 'due' not in task:
                nodue_list.append(task)
            else:
                due_list.append(task)
        tasks = due_list

        try:
            # Group by date and then by project
            tasks.sort(key=itemgetter('due', 'project'))
        except KeyError:  # If no 'project' attribute for one or more tasks
            tasks.sort(key=itemgetter('due'))

        self.tasks = nodue_list + tasks

    def run_report(self):
        """
        Compile and print the task report.
        """
        wdays = ["MON", "TUE", "WED", "THU", "FRI", "SAT", "SUN"]
        letters = 3     # No of letters to use for wday names. 1 - 3
        istty = True
        indent = letters      # The indent per week day
# TODO "indent" is used and defined here an in construct_cmdline.  Define once?
        if istty:  # This is currently hard coded, but can be an input.
            term = Terminal()
        else:
            term = Terminal(stream="not tty")  # When not run from a tty
        # Calcs how many task lines can fit onto the screen.
        taskspace = (term.height if term.is_a_tty else 40) - (5 + letters)

        # Compile the line showing each Monday's date.
        dateline = self.weekstart.strftime("%d %b %Y")
        if self.weeks > 1:  # Add additional Mondays if required
            for week in range(1, self.weeks):  # i.e. week 1 is the second week.
                # No of spaces to add on to existing dateline before
                # inserting next date
                weekindent = len(wdays) * week * indent - len(dateline)
                dateline = dateline + ' ' * weekindent + (self.weekstart + \
                    timedelta(days=7 * week)).strftime("%d %b %Y")  # Position

        # Compile the day header sting (includes newlines)
        dayheader = ''
        for lineNo in range(letters):
            for index, day in enumerate(wdays * self.weeks):
                #  add the letter and spacing to indent for each day and makes mondays bold
                ch = day[lineNo]
                if (day == "MON" ):
                    ch = term.bold(ch)

                if (self.weekstart + timedelta(days=index) == date.today()):
                    ch = term.red(ch)

                dayheader = dayheader + ch + ' ' * (indent - 1)
            dayheader = dayheader + '\n'

        # Compile the multiline string containing the tasklines
        taskstring = ""
        for task in self.tasks:   # Step through list of task dictionary objects
            taskline, tdate = self.compile_taskline(task)
            if tdate.date() < date.today():
                # Add newline if not end of list and colour red
                taskstring = taskstring + ('\n' if len(taskstring) != 0 else ''
                    ) + term.red(taskline)
            elif tdate.date() == date.today():
                taskstring = taskstring + '\n' + term.yellow(taskline)
            elif tdate.date() > date.today():
                taskstring = taskstring + '\n' + taskline

        # Removes lines that will not fit onto screen
        terminal_lines = ''.join(taskstring.splitlines(True)[0:taskspace])
        print dateline + '\n' + dayheader + terminal_lines


    def compile_taskline(self, task):
        """
        Compile a task line to be used in the task selector or in the
        task report.
        """
        indent = 3      # The indent per week day

        if 'due' not in task:
        # Indents the task by 6 days at top of list to show that it does not \
        # have a due date.  datetime.min.time() is a constant for midnight
            tdate = datetime.combine(self.weekstart + timedelta(days=6), \
                datetime.min.time())  # Converts the date back to a datetime.

        else:
                # This assumes GMT+2 - change this for your timezone
            tdate = datetime.strptime(task["due"], "%Y%m%dT%H%M%SZ") + \
                timedelta(hours=2)  # Assume tasks are ordered by due date
        daydiff = tdate.date() - self.weekstart
        daydiff = daydiff.days
        taskline = indent * daydiff * " " + repr(task["id"]) + " (" + \
            (task["project"] if "project" in task else "none") \
            + ")" + ("*" if "annotations" in task else " ") \
            + (task["description"].upper()
            if ("priority" in task and task["priority"] == "H")
            else task["description"])
        return taskline, tdate


def main():
    report = TaskReport()

if __name__ == '__main__':
    main()
