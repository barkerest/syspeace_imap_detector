using System;
using System.Collections.Generic;
using System.Diagnostics.Eventing.Reader;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security;
using System.Text;
using System.Text.RegularExpressions;
using System.Threading;
using Syspeace.ProviderInterface;
using ThreadState = System.Threading.ThreadState;

/*
 * ImapDetector (https://github.com/barkerest/syspeace_imap_detector)
 *
 * This is a detector for Syspeace (https://syspeace.com) that will detect login attempts against the IMAP
 * service in an Exchange environment.  This has been tested with Exchange 2010.
 *
 * Copyright (c) 2019 Beau Barker (beau@barkerest.com)
 * All Rights Reserved
 *
 * Licensed under the MIT license.
 * https://opensource.org/licenses/MIT
 */


namespace ImapDetector
{
	public class ImapDetectorRule : BaseRule
	{
	}

	[Serializable]
	public class ImapDetectorObservation : BaseObservation
	{
		[ExtraInfo("imapsession")]
		public long? SessionID { get; set; }
	}

	internal static class Helpers
	{
		public static bool CloseTo(this DateTime date, DateTime other, double maxSeconds = 0.5)
		{
			var diff = Math.Abs(date.Subtract(other).TotalSeconds);
			return diff <= maxSeconds;
		}
	}

	[Detector(4)]
	public class ImapDetector : IDetector<ImapDetectorRule, ImapDetectorObservation>
	{
		#region Config Object

		private class Config
		{
			public Config(string path)
			{
				if (!File.Exists(path)) return;

				foreach (var line in File.ReadLines(path))
				{
					if (string.IsNullOrWhiteSpace(line)) continue;

					var chunks = line.Split(new[] {':'}, 2);

					var val = chunks.Length == 2 ? chunks[1].Trim().ToLower() : "";

					switch (chunks[0].ToLower())
					{
						case "checkeventlog":
							CheckEventLog = new[] {"true", "yes", "1", "t", "y"}.Contains(val);
							break;
						case "maxageinminutestoreport":
							if (long.TryParse(val, out var minutes) && minutes > 0 && minutes < 1440)
							{
								MaxAgeInMinutesToReport = minutes;
							}

							break;
						case "lastobservationtime":
							if (DateTime.TryParse(val, out var dateValue))
							{
								LastObservationTime = dateValue;
							}

							break;

						case "lastobservationsession":
							if (long.TryParse(val, out var session))
							{
								LastObservationSession = session;
							}

							break;

						case "maxdaystoretainlogs":
							if (long.TryParse(val, out var logAge) && logAge >= 1 && logAge <= 365)
							{
								MaxDaysToRetainLogs = logAge;
							}

							break;

						case "logdirectory":
							LogDirectory = val;
							break;
					}
				}
			}

			public bool CheckEventLog { get; } = true;

			public long MaxAgeInMinutesToReport { get; } = 60;

			public long MaxDaysToRetainLogs { get; } = 7;

			public DateTime? LastObservationTime { get; set; }

			public long? LastObservationSession { get; set; }

			public string LogDirectory { get; }

			public override string ToString()
			{
				var time = LastObservationTime?.ToUniversalTime().ToString("yyyy-MM-dd'T'HH:mm:ss'Z'");
				return
					$@"# IMAP Detector Configuration
# CAUTION: Changes to this file will be discarded if program is running.

# True to query the event log for user names
CheckEventLog: {CheckEventLog}

# Between 1 and 1440
MaxAgeInMinutesToReport: {MaxAgeInMinutesToReport}

# Explicitly set the directory to search for log files
LogDirectory: {LogDirectory}

# How many days should log files be left in the log directory (between 1 and 365)
MaxDaysToRetainLogs: {MaxDaysToRetainLogs}

# Automatically set when reported
LastObservationTime: {time}
LastObservationSession: {LastObservationSession}
".Replace("\r\n", "\n").Replace("\n", "\r\n");
			}
		}

		#endregion

		#region LogRecord Object

		private class LogRecord
		{
			public DateTime LogDate { get; set; }

			public long SessionID { get; set; }

			public string ClientIpAndPort { get; set; }

			public string ClientIp => ClientIpAndPort.IndexOf(':') > -1
				? ClientIpAndPort.Split(new[] {':'}, 2)[0]
				: ClientIpAndPort;

			public int ClientPort => ClientIpAndPort.IndexOf(':') > -1
				? int.Parse(ClientIpAndPort.Split(new[] {':'}, 2)[1])
				: 0;

			public string Command { get; set; }

			public string Context { get; set; }

			public string User { get; set; }

			public bool IsLoginFailure =>
			(
				"authenticate".Equals(Command, StringComparison.OrdinalIgnoreCase) &&
				(Context ?? "").ToLower().Contains("authfailed")
			) || (
				"login".Equals(Command, StringComparison.OrdinalIgnoreCase) &&
				(Context ?? "").ToLower().Contains("logonfailed")
			);

			public ImapDetectorObservation ToObservation()
			{
				return new ImapDetectorObservation()
				{
					IP           = ClientIp,
					SessionID    = SessionID,
					Success      = false,
					User         = User,
					UTCTimestamp = LogDate.ToUniversalTime()
				};
			}
		}

		#endregion

		#region Constructor and UseLocation

		private string _configFile;

		public ImapDetector()
		{
			_configFile = (Path.GetDirectoryName(typeof(ImapDetector).Assembly.Location) ??
						   Environment.CurrentDirectory)
						  .TrimEnd('/', '\\') + "/ImapDetector.config";
		}

		public void UseLocation(string pathToDetectorFolder)
		{
			_configFile = pathToDetectorFolder.Replace('\\', '/').TrimEnd('/') + "/ImapDetector.config";
			File.WriteAllText(_configFile, new Config(_configFile).ToString());
		}

		#endregion

		#region GetDefaultRules

		public ImapDetectorRule[] GetDefaultRules()
		{
			return new[]
			{
				new ImapDetectorRule()
				{
					Name             = "Catch all",
					IsEnabled        = true,
					TriggerWindow    = TimeSpan.FromHours(2),
					OccurrencesCount = 5,
					LockoutDuration  = TimeSpan.FromHours(2),
					Priority         = 1
				},
			};
		}

		#endregion

		#region FindExchangeInstances

		private static IEnumerable<string> FindExchangeInstances()
		{
			var ret = new List<string>();

			var env = Environment.GetEnvironmentVariable("EXCHANGEINSTALLPATH");
			if (!string.IsNullOrWhiteSpace(env))
			{
				env = env.Trim().Replace('\\', '/').TrimEnd('/');
				ret.Add(env);
			}

			try
			{
				using (var parentKey =
					Microsoft.Win32.Registry.LocalMachine.OpenSubKey("SOFTWARE\\MICROSOFT\\EXCHANGESERVER"))
				{
					if (parentKey is null) return ret;
					foreach (var childKeyName in parentKey.GetSubKeyNames())
					{
						try
						{
							using (var childKey = parentKey.OpenSubKey($"{childKeyName}\\SETUP"))
							{
								if (childKey is null) continue;
								var path = childKey.GetValue("MsiInstallPath", "").ToString();
								if (string.IsNullOrWhiteSpace(path)) continue;
								path = path.Trim().Replace('\\', '/').TrimEnd('/');
								if (ret.FindIndex((p) => p.Equals(path, StringComparison.OrdinalIgnoreCase)) < 0)
								{
									ret.Add(path);
								}
							}
						}
						catch (Exception e) when (
							e is SecurityException ||
							e is UnauthorizedAccessException ||
							e is IOException
						)
						{
							// ignore
						}
					}
				}
			}
			catch (Exception e) when (
				e is SecurityException ||
				e is UnauthorizedAccessException ||
				e is IOException
			)
			{
				// ignore
			}

			return ret;
		}

		#endregion

		#region ParseLog

		private static int FindFieldEnd(ref string line, Func<string> getMoreData)
		{
			var q = false;
			var x = 0;

			while (true)
			{
				for (var i = x; i < line.Length; i++)
				{
					var c = line[i];
					if (c == ',' && !q) return i;
					if (c == '"') q = !q;
				}

				if (!q) return line.Length;

				x = line.Length + 2;

				var next = getMoreData();
				if (next is null) return line.Length;

				line += "\r\n" + next;
			}
		}

		private static string GetNextField(ref string line, Func<string> getMoreData)
		{
			var length = FindFieldEnd(ref line, getMoreData);

			var ret = line.Substring(0, length);
			line = length >= line.Length
				? null // last field in a line 
				: line.Substring(length + 1); // field separated by a comma.

			if (length > 0 && ret[0] == '"' && ret[length - 1] == '"')
				ret = ret.Substring(1, length - 2);

			ret = ret.Replace("\"\"", "\"");

			return ret;
		}

		private static string[] GetFields(string line, Func<string> getMoreData)
		{
			var ret = new List<string>();

			while (!(line is null))
			{
				ret.Add(GetNextField(ref line, getMoreData));
			}

			return ret.ToArray();
		}


		private static IEnumerable<LogRecord> ParseLog(string logFile)
		{
			var logDateIndex   = 0;
			var sessionIdIndex = 1;
			var clientIpIndex  = 4;
			var commandIndex   = 9;
			var contextIndex   = 11;
			var minColumns     = 12;
			var ret            = new List<LogRecord>();


			using (var stream = File.Open(logFile, FileMode.Open, FileAccess.Read, FileShare.ReadWrite))
			using (var reader = new StreamReader(stream, Encoding.UTF8))
			{
				// ReSharper disable once AccessToDisposedClosure
				string GetMoreData() => reader.ReadLine();

				var line = reader.ReadLine();
				if (line is null) return ret;
				if (line.Length > 0 && line[0] != '#')
				{
					// process header.
					var fields = GetFields(line, GetMoreData);

					logDateIndex   = -1;
					sessionIdIndex = -1;
					clientIpIndex  = -1;
					commandIndex   = -1;
					contextIndex   = -1;

					for (var i = 0; i < fields.Length; i++)
					{
						switch (fields[i].ToLower())
						{
							case "datetime":
								logDateIndex = i;
								break;
							case "sessionid":
								sessionIdIndex = i;
								break;
							case "cip":
								clientIpIndex = i;
								break;
							case "command":
								commandIndex = i;
								break;
							case "context":
								contextIndex = i;
								break;
						}
					}

					if (logDateIndex < 0 || sessionIdIndex < 0 || clientIpIndex < 0 ||
						commandIndex < 0 || contextIndex < 0)
					{
						throw new InvalidDataException("The header row is missing one or more fields.");
					}

					minColumns = new[]
					{
						logDateIndex, sessionIdIndex, clientIpIndex, commandIndex, contextIndex
					}.Max();
				}

				line = reader.ReadLine();
				while (line != null)
				{
					if (line.Length > 0 && line[0] != '#')
					{
						var fields = GetFields(line, GetMoreData);
						if (fields.Length >= minColumns)
						{
							ret.Add(
								new LogRecord()
								{
									LogDate         = DateTime.Parse(fields[logDateIndex]),
									ClientIpAndPort = fields[clientIpIndex],
									Command         = fields[commandIndex],
									Context         = fields[contextIndex],
									SessionID =
										long.Parse(fields[sessionIdIndex], NumberStyles.AllowHexSpecifier),
									User = "imap-user"
								});
						}
					}

					line = reader.ReadLine();
				}
			}

			return ret;
		}

		#endregion

		#region Observer

		private IDetectorObservationListener<ImapDetectorObservation> _listener;
		private Thread                                                _worker;

		private IEnumerable<string> AvailableLogFiles(Config cfg)
		{
			// search the log directories for new log entries.
			if (string.IsNullOrWhiteSpace(cfg.LogDirectory))
			{
				foreach (var dir in LogDirectories)
				{
					if (!Directory.Exists(dir)) continue;
					foreach (var fn in Directory.GetFiles(dir, "*.log", SearchOption.TopDirectoryOnly))
					{
						yield return fn;
					}
				}
			}
			else
			{
				if (!Directory.Exists(cfg.LogDirectory)) yield break;
				foreach (var fn in Directory.GetFiles(cfg.LogDirectory, "*.log", SearchOption.TopDirectoryOnly))
				{
					yield return fn;
				}
			}
		}

		private void Worker()
		{
			if (_listener is null) return;

			var logRecords = new List<LogRecord>();
			var cfg        = new Config(_configFile);

			LogMessage("Starting new observation loop.");
			LogMessage($"Last logged IMAP session: {cfg.LastObservationSession}");
			LogMessage($"Last logged IMAP time: {cfg.LastObservationTime}");
			LogMessage($"Searching for matching events: {cfg.CheckEventLog}");
			LogMessage($"Max days to retain logs: {cfg.MaxDaysToRetainLogs}");
			LogMessage(
				"Log directory: " +
				(string.IsNullOrWhiteSpace(cfg.LogDirectory) ? "(auto discovered)" : cfg.LogDirectory));

			// support both daily and hourly log files.
			var rexLogFile = new Regex(@"^imap4(\d{8}|\d{10})(?:-\d+)?\.log$", RegexOptions.IgnoreCase);

			bool QuitNow() => _listener?.CancellationToken.IsCancellationRequested ?? true;

			try
			{
				while (!QuitNow())
				{
					logRecords.Clear();

					var minLogDate = cfg.LastObservationTime ?? DateTime.Now.AddMinutes(-cfg.MaxAgeInMinutesToReport);
					var minLogSess = cfg.LastObservationSession ?? 0;
					var fnMinTime  = long.Parse(minLogDate.ToUniversalTime().ToString("yyyyMMddHH"));

					// search the log directories for new log entries.
					foreach (var filename in AvailableLogFiles(cfg))
					{
						if (QuitNow()) return;

						var match = rexLogFile.Match(Path.GetFileName(filename) ?? "");
						if (!match.Success) continue;
						var tss                  = match.Groups[1].Value;
						if (tss.Length == 8) tss += "24";
						var ts                   = long.Parse(tss);
						if (ts < fnMinTime) continue;
						logRecords.AddRange(ParseLog(filename));
						logRecords.RemoveAll(
							(r) => (r.LogDate < minLogDate && !r.LogDate.CloseTo(minLogDate)) ||
								   (r.LogDate.CloseTo(minLogDate) && r.SessionID <= minLogSess) ||
								   !r.IsLoginFailure);
					}

					if (QuitNow()) return;

					if (!logRecords.Any()) continue;

					// check the event log for user names if configured to do so.
					var identified = 0;
					if (cfg.CheckEventLog)
					{
						var ts = minLogDate.AddSeconds(-5)
							.ToUniversalTime()
							.ToString("yyyy-MM-dd'T'HH:mm:ss'.000Z'");
						var evQuery = $"*[System[(EventID=4625) and (TimeCreated[@SystemTime>='{ts}'])]]";
						var evLog   = new EventLogQuery("Security", PathType.LogName, evQuery);
						var selector = new EventLogPropertySelector(
							new[]
							{
								"Event/EventData/Data[@Name='ProcessName']",
								"Event/EventData/Data[@Name='TargetUserName']"
							});
						using (var evReader = new EventLogReader(evLog))
						{
							var ev = evReader.ReadEvent();
							while (ev != null)
							{
								if (QuitNow()) return;
								if (ev is EventLogRecord er && er.TimeCreated.HasValue)
								{
									var props = er.GetPropertyValues(selector).Select(x => x?.ToString() ?? "")
										.ToArray();

									if (!string.IsNullOrWhiteSpace(props[1]) &&
										props[0].EndsWith(
											"Microsoft.Exchange.Imap4.exe", StringComparison.OrdinalIgnoreCase)
									)
									{
										var evTime = er.TimeCreated.GetValueOrDefault();
										var logEntry = logRecords
											.Where(r => r.LogDate.CloseTo(evTime, 2.0))
											.OrderBy(r => Math.Abs(r.LogDate.Subtract(evTime).TotalSeconds))
											.FirstOrDefault();

										if (logEntry != null && logEntry.User == "imap-user")
										{
											identified++;
											logEntry.User = props[1];
										}
									}
								}

								ev = evReader.ReadEvent();
							}
						}
					}

					if (logRecords.Count == 1)
					{
						LogMessage(
							identified > 0
								? "Found 1 login attempt and identified the user."
								: "Found 1 login attempt and did not identify the user.");
					}
					else
					{
						LogMessage(
							$"Found {logRecords.Count} login attempts and identified the user in {identified} of them.");
					}

					// report the observations to the listener.
					foreach (var record in logRecords)
					{
						if (QuitNow()) return;
						_listener.RecordObservation(record.ToObservation());
						if (record.SessionID > cfg.LastObservationSession.GetValueOrDefault())
							cfg.LastObservationSession = record.SessionID;
						if (record.LogDate > cfg.LastObservationTime.GetValueOrDefault())
							cfg.LastObservationTime = record.LogDate;
					}

					// update the configuration.
					File.WriteAllText(_configFile, cfg.ToString());

					// purge older log files.
					minLogDate = DateTime.Today.AddDays(-cfg.MaxDaysToRetainLogs);
					fnMinTime  = long.Parse(minLogDate.ToUniversalTime().ToString("yyyyMMdd'24'"));
					foreach (var filename in AvailableLogFiles(cfg))
					{
						var match = rexLogFile.Match(Path.GetFileName(filename) ?? "");
						if (!match.Success) continue;
						var tss                  = match.Groups[1].Value;
						if (tss.Length == 8) tss += "24";
						var ts                   = long.Parse(tss);
						if (ts >= fnMinTime) continue;
						try
						{
							File.Delete(filename);
						}
						catch (Exception e) when (
							e is IOException ||
							e is ArgumentException ||
							e is NotSupportedException ||
							e is UnauthorizedAccessException
						)
						{
							// ignore
						}
					}

					// wait a minute before the next pass.
					var timeout = DateTime.Now.AddMinutes(1);
					while (DateTime.Now < timeout && !QuitNow())
					{
						Thread.Sleep(10);
					}
				}
			}
			finally
			{
				try
				{
					File.WriteAllText(_configFile, cfg.ToString());
				}
				catch (Exception e) when (
					e is ArgumentException ||
					e is IOException ||
					e is UnauthorizedAccessException ||
					e is NotSupportedException ||
					e is SecurityException
				)
				{
					// Ignore.
				}

				LogMessage("Stopping observation loop.");
			}
		}

		public bool ObserverRunning => _worker != null &&
									   _worker.ThreadState != ThreadState.Aborted &&
									   _worker.ThreadState != ThreadState.Stopped;

		public void StartObserver(IDetectorObservationListener<ImapDetectorObservation> observationListener)
		{
			if (ObserverRunning) return;

			_listener = observationListener;
			_worker   = new Thread(Worker);
			_worker.Start();
		}

		#endregion

		#region Observation Checking

		public bool RuleMatchesObservation(ImapDetectorRule rule, ImapDetectorObservation observation)
		{
			return true;
		}

		public bool IsIgnorableDuplicate(
			ImapDetectorObservation earlierObservation, ImapDetectorObservation laterObservation)
		{
			return earlierObservation.UTCTimestamp == laterObservation.UTCTimestamp &&
				   earlierObservation.SessionID == laterObservation.SessionID;
		}

		public bool IsIgnorableOtherReason(ImapDetectorObservation observation)
		{
			return false;
		}

		#endregion

		#region Formatting Output

		public KeyValuePair<string, string>[] FormatObservationInfo(ImapDetectorObservation observation)
		{
			return new[] {new KeyValuePair<string, string>("IMAP Session ID", observation.SessionID?.ToString() ?? "")};
		}

		public KeyValuePair<string, string>[] FormatRuleInfo(ImapDetectorRule rule)
		{
			return new KeyValuePair<string, string>[0];
		}

		public string UserOrOtherOriginDescription(ImapDetectorObservation observation)
		{
			return observation.User;
		}

		public string FormatCompositeAccountName(ImapDetectorObservation observation)
		{
			return observation.User;
		}

		public string GetAccessReportFormattedExtra(ImapDetectorObservation observation)
		{
			return "IMAP Session " + (observation.SessionID?.ToString() ?? "(missing)");
		}

		#endregion

		#region Logging

		private string _logPath;

		private string LogPath
		{
			get
			{
				if (_logPath != null) return _logPath;

				var dir = Path.GetTempPath().TrimEnd('\\', '/') + "/ImapDetector";

				try
				{
					if (!Directory.Exists(dir))
					{
						Directory.CreateDirectory(dir);
					}

					var testFile = dir + "/test.write";
					File.WriteAllText(testFile, "This is only a test file and can be safely deleted.");
					File.Delete(testFile);

					_logPath = dir + "/ImapDetector.log";
				}
				catch (Exception e) when (
					e is IOException ||
					e is UnauthorizedAccessException ||
					e is SecurityException ||
					e is NotSupportedException ||
					e is ArgumentException
				)
				{
					_logPath = Path.GetTempFileName();
				}

				return _logPath;
			}
		}

		private Stream       _logStream;
		private StreamWriter _logWriter;

		private StreamWriter LogStream
		{
			get
			{
				if (_logWriter != null) return _logWriter;
				_logStream = File.Open(LogPath, FileMode.Create, FileAccess.Write, FileShare.Read);
				_logWriter = new StreamWriter(_logStream);
				return _logWriter;
			}
		}

		private void LogMessage(string msg)
		{
			LogStream.WriteLine("{0:yyyy-MM-dd HH:mm:ss}  {1}", DateTime.Now, msg);
			LogStream.Flush();
			LogStream.BaseStream.Flush();
		}

		#endregion

		#region Properties

		public string FriendlyDetectorName { get; } = "Exchange IMAP4";

		public string DetectorType { get; } = "com.barkerest.ImapDetector";

		public string UsageWarning { get; } = null;

		private string[] _logDirectories;

		private string[] LogDirectories
		{
			get
			{
				if (_logDirectories != null) return _logDirectories;
				var tmp = new List<string>();
				LogMessage("Looking for log paths...");

				// Set the environment variable "ImapLogPath" to use a non-standard log path.
				var env = Environment.GetEnvironmentVariable("IMAPLOGPATH");
				if (!string.IsNullOrWhiteSpace(env))
				{
					LogMessage("Environment variable is set.");
					env = env.Trim().Replace('\\', '/').TrimEnd('/');
					tmp.Add(env);
				}

				foreach (var instancePath in FindExchangeInstances())
				{
					var path = instancePath + "/Logging/Imap4";
					if (tmp.FindIndex((p) => p.Equals(path, StringComparison.CurrentCultureIgnoreCase)) < 0)
					{
						LogMessage($"Including Exchange instance at '{instancePath}'.");
						tmp.Add(path);
					}
				}

				_logDirectories = tmp.ToArray();
				return _logDirectories;
			}
		}

		public ProviderAvailabilityResult CanRunInEnvironment
		{
			get
			{
				var cfg = new Config(_configFile);
				if (string.IsNullOrWhiteSpace(cfg.LogDirectory))
				{
					LogMessage("Searching for discoverable log directories...");
					foreach (var dir in LogDirectories)
					{
						if (Directory.Exists(dir))
							return ProviderAvailabilityResult.IsAvailable;
					}
				}
				else
				{
					LogMessage("Searching for configured log directory...");
					if (Directory.Exists(cfg.LogDirectory))
					{
						return ProviderAvailabilityResult.IsAvailable;
					}
				}

				return ProviderAvailabilityResult.IsUnavailableBecause(
					"log directory not found, set \"ImapLogPath\" environment variable.");
			}
		}

		#endregion
	}
}
