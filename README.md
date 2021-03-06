# ImapDetector

The [ImapDetector](https://github.com/barkerest/syspeace_imap_detector) is a
detector for [Syspeace](https://syspeace.com) that will detect login attempts
generated by the IMAP service in a Microsoft Exchange environment.

This detector has been tested with Syspeace 3.1.0.0 and Microsoft Exchange 2010.

## How it works

The detector reads the log files generated by the IMAP service and processes the
records related to login failures.  These will be either "authenticate" or 
"login" commands that are marked as failed.

If configured, the detector will then search the Windows event log for events
4625 that are generated by the Microsoft.Exchange.Imap4.exe process.  If it 
finds a matching event, then it uses the target user name from the event to 
update the log record.

Log records will then be reported as observations to Syspeace and Syspeace 
handles the rest.

## How to use

1. Locate your Syspeace installation path.  
   This is usually "C:\Program Files\Treetop\Syspeace"
2. Copy the "Syspeace.ProviderInterface.dll" file from the Syspeace installation
   path to this solution's base path.
3. Build this solution.
4. Create a "providers" folder in your Syspeace installation path if it is 
   not there.
5. Create a "ImapDetector.provider" folder in your "providers" folder.  
   eg - C:\Program Files\Treetop\Syspeace\providers\ImapDetector.provider
6. Copy the ImapDetector.dll file you built in step 3 to your new 
   ImapDetector.provider folder.
7. Restart the Syspeace service.
8. Enable protocol logging in Microsoft Exchange.
   ```powershell
   Set-ImapSettings -ProtocolLogEnabled $True -LogFileRollOverSettings Hourly
   ```

## Configuration

The detector will read its configuration from the ImapDetector.config file in
the ImapDetector.provider folder.  It will create the file automatically and 
will update it as it runs.

The file should not be edited if the Syspeace service is running.

There are several options that can be tweaked.

- **CheckEventLog**  
  Set to true to have the event log checked for events to identify users in log
  events.  Set to false to skip checking the event log.  If false, all users
  will be reported as "imap-user".  If true, most users will be identified, but
  there might be a performance penalty from querying the event log.
- **LogDirectory**  
  The default behavior is to hunt down Microsoft Exchange via the environment
  and registry.  When an Exchange installation is located, then a directory
  named "Imap4" is looked for in the "Logging" directory.  
  eg - C:\Program Files\Microsoft\Exchange\V14\Logging\Imap4
- **MaxAgeInMinutesToReport**  
  When the ImapDetector first fires up, it can report logged events from the 
  recent past.  The default value is 60 minutes, but this can be anywhere from
  1 minute up to 1440 minutes (1 day).
- **MaxDaysToRetainLogs**  
  The Microsoft Exchange Imap protocol logs don't get cleaned up automatically.
  Since we're using them, we will clean them up.  The default value is 7, but 
  this can be anywhere from 1 to 365 days.

## License

ImapDetector is available under the MIT license.

> Copyright 2019 Beau Barker
>
> Permission is hereby granted, free of charge, to any person obtaining a copy 
> of this software and associated documentation files (the "Software"), to deal
> in the Software without restriction, including without limitation the rights
> to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
> copies of the Software, and to permit persons to whom the Software is
> furnished to do so, subject to the following conditions:
> 
> The above copyright notice and this permission notice shall be included in
> all copies or substantial portions of the Software.
> 
> THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
> IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
> FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
> AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
> LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
> OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
> SOFTWARE.
