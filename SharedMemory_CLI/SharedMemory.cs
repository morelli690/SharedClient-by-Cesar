using System;
using System.Text;
using System.Security.AccessControl;
using System.Threading;
using System.IO.MemoryMappedFiles;

namespace SharedMemory_CLI
{
    public class SharedMemory
    {
        const string FullMapName = "Global\\SharedMem";

        readonly EventWaitHandle Event;
        readonly MemoryMappedFile File;
        readonly MemoryMappedViewStream Stream;

        public SharedMemory()
        {
            Event = EventInitialisation("Global\\ReadyRead");

            Console.WriteLine("Waiting on the event, please load your driver now.");

            Event.WaitOne();
            Event.Reset();

            try
            {
                File = MemoryMappedFile.CreateOrOpen(
                        FullMapName, 4096, MemoryMappedFileAccess.ReadWrite);

                Stream = File.CreateViewStream();
                Console.WriteLine("Shared memory created.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("CreateSharedMemory failed error: {0}", ex.Message);
            }
        }

        private EventWaitHandle EventInitialisation(string eventName)
        {
            EventWaitHandle ewh;
            try
            {
                ewh = EventWaitHandle.OpenExisting(eventName);
            }
            catch (WaitHandleCannotBeOpenedException)
            {
                string user = Environment.UserDomainName + "\\"
                    + Environment.UserName;
                EventWaitHandleSecurity ewhSec =
                    new EventWaitHandleSecurity();

                EventWaitHandleAccessRule rule =
                    new EventWaitHandleAccessRule(user,
                        EventWaitHandleRights.Synchronize |
                        EventWaitHandleRights.Modify,
                        AccessControlType.Deny);
                ewhSec.AddAccessRule(rule);

                rule = new EventWaitHandleAccessRule(user,
                    EventWaitHandleRights.ReadPermissions |
                    EventWaitHandleRights.ChangePermissions,
                    AccessControlType.Allow);
                ewhSec.AddAccessRule(rule);

                ewh = new EventWaitHandle(true,
                    EventResetMode.AutoReset,
                    eventName,
                    out bool wasCreated,
                    ewhSec);
            }
            catch (UnauthorizedAccessException)
            {
                ewh = EventWaitHandle.OpenExisting(eventName,
                        EventWaitHandleRights.ReadPermissions |
                        EventWaitHandleRights.ChangePermissions);

                EventWaitHandleSecurity ewhSec = ewh.GetAccessControl();

                string user = Environment.UserDomainName + "\\"
                    + Environment.UserName;

                EventWaitHandleAccessRule rule =
                    new EventWaitHandleAccessRule(user,
                        EventWaitHandleRights.Synchronize |
                        EventWaitHandleRights.Modify,
                        AccessControlType.Deny);

                ewhSec.RemoveAccessRule(rule);

                rule = new EventWaitHandleAccessRule(user,
                    EventWaitHandleRights.Synchronize |
                    EventWaitHandleRights.Modify,
                    AccessControlType.Allow);

                ewhSec.AddAccessRule(rule);

                ewh.SetAccessControl(ewhSec);

                ewh = EventWaitHandle.OpenExisting(eventName);
            }

            return ewh;
        }

        public void ClearPIDDBCacheTable()
        {
            try
            {
                string Message = "ClearPiDDBCacheTable";
                byte[] byteArray = Encoding.ASCII.GetBytes(Message);
                Stream.Write(byteArray, 0, byteArray.Length);

                Event.WaitOne();

                byte[] buffer = new byte[20];
                Stream.Position = 0;
                Stream.Read(buffer, 0, buffer.Length);
                Console.WriteLine(Encoding.ASCII.GetString(buffer).Split('\0')[0]);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Threw exception: {0}", ex.Message);
            }
        }

        public void ClearMMUnloadedDrivers()
        {
            try
            {
                string Message = "ClearMMUnloadedDrivers";
                byte[] byteArray = Encoding.ASCII.GetBytes(Message);
                Stream.Write(byteArray, 0, byteArray.Length);

                Event.WaitOne();

                byte[] buffer = new byte[20];
                Stream.Position = 0;
                Stream.Read(buffer, 0, buffer.Length);
                Console.WriteLine(Encoding.ASCII.GetString(buffer).Split('\0')[0]);
            }
            catch (Exception ex)
            {
                Console.WriteLine("Threw exception: {0}", ex.Message);
            }
        }
    }
}
