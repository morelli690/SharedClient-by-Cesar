using System;
using System.Text;
using System.Security.AccessControl;
using System.Threading;
using System.IO.MemoryMappedFiles;

namespace SharedInterface_by_Cesar
{
    public class SharedInterface
    {
        /// <summary>
        /// Hi! Cesar here, welcome to shared driver interface in c#!!!
        /// First you need to run Usermode (this), call CreateSharedEvents(),
        /// Second you need to load your driver (ex.: OSR driver loader,drvmap)
        /// Third you can now call CreateSharedMemory(), and desired command(s) (ex.: ClearPIDCache())
        /// </summary>    

        #region CreateSharedEvents
        public string Event_DataArrived_Name = "Global\\DataArrived";
        public string Event_Trigger_Name = "Global\\trigger";
        public string Event_Ready_Name = "Global\\ReadyRead";

        public static EventWaitHandle SharedEvent_dataarv;
        public static EventWaitHandle SharedEvent_trigger;
        public static EventWaitHandle SharedEvent_ready2read;
        #endregion
        #region CreateSharedMemory
        // In terminal services: The name can have a "Global\" or "Local\"  
        // prefix to explicitly create the object in the global or session  
        // namespace. The remainder of the name can contain any character except 
        // the backslash character (\). For more information, see:  
        // http://msdn.microsoft.com/en-us/library/aa366537.aspx 
        internal const string MapPrefix = "Global\\";
        internal const string MapName = "SharedMem";//SampleMap
        internal const string FullMapName = MapPrefix + MapName;//_EventName

        // The number of bytes of a file mapping to map to the view. All bytes of  
        // the view must be within the maximum size of the file mapping object.  
        // If VIEW_SIZE is 0, the mapping extends from the offset (VIEW_OFFSET)  
        // to the end of the file mapping. 
        Int64 ViewSize = 4096;
        MemoryMappedFile memoryMappedFile;
        MemoryMappedViewStream stream;
        #endregion

        public void CreateSharedEvents()
        {
            SharedEvent_dataarv = EventInicialization(Event_DataArrived_Name);
            SharedEvent_trigger = EventInicialization(Event_Trigger_Name);
            SharedEvent_ready2read = EventInicialization(Event_Ready_Name);

        }
        private static EventWaitHandle EventInicialization(string eventName)
        {
            //source: https://docs.microsoft.com/pt-br/dotnet/api/system.threading.eventwaithandle.-ctor?view=netframework-4.8#System_Threading_EventWaitHandle__ctor_System_Boolean_System_Threading_EventResetMode_System_String_System_Boolean__System_Security_AccessControl_EventWaitHandleSecurity_
            string ewhName = eventName;

            EventWaitHandle ewh = null;
            bool doesNotExist = false;
            bool unauthorized = false;

            // The value of this variable is set by the event
            // constructor. It is true if the named system event was
            // created, and false if the named event already existed.
            //
            bool wasCreated;

            // Attempt to open the named event.
            try
            {
                // Open the event with (EventWaitHandleRights.Synchronize
                // | EventWaitHandleRights.Modify), to wait on and 
                // signal the named event.
                //
                ewh = EventWaitHandle.OpenExisting(ewhName);
            }
            catch (WaitHandleCannotBeOpenedException)
            {
                Console.WriteLine("Named event does not exist.");
                doesNotExist = true;
            }
            catch (UnauthorizedAccessException ex)
            {
                Console.WriteLine("Unauthorized access: {0}", ex.Message);
                unauthorized = true;
            }

            // There are three cases: (1) The event does not exist.
            // (2) The event exists, but the current user doesn't 
            // have access. (3) The event exists and the user has
            // access.
            //
            if (doesNotExist)
            {
                // The event does not exist, so create it.

                // Create an access control list (ACL) that denies the
                // current user the right to wait on or signal the 
                // event, but allows the right to read and change
                // security information for the event.
                //
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

                // Create an EventWaitHandle object that represents
                // the system event named by the constant 'ewhName', 
                // initially signaled, with automatic reset, and with
                // the specified security access. The Boolean value that 
                // indicates creation of the underlying system object
                // is placed in wasCreated.
                //
                ewh = new EventWaitHandle(true,
                    EventResetMode.AutoReset,
                    ewhName,
                    out wasCreated,
                    ewhSec);

                // If the named system event was created, it can be
                // used by the current instance of this program, even 
                // though the current user is denied access. The current
                // program owns the event. Otherwise, exit the program.
                // 
                if (wasCreated)
                {
                    Console.WriteLine("Created the named event.");
                }
                else
                {
                    Console.WriteLine("Unable to create the event.");
                    return null;
                }
            }
            else if (unauthorized)
            {
                // Open the event to read and change the access control
                // security. The access control security defined above
                // allows the current user to do this.
                //
                try
                {
                    ewh = EventWaitHandle.OpenExisting(ewhName,
                        EventWaitHandleRights.ReadPermissions |
                        EventWaitHandleRights.ChangePermissions);

                    // Get the current ACL. This requires 
                    // EventWaitHandleRights.ReadPermissions.
                    EventWaitHandleSecurity ewhSec = ewh.GetAccessControl();

                    string user = Environment.UserDomainName + "\\"
                        + Environment.UserName;

                    // First, the rule that denied the current user 
                    // the right to enter and release the event must
                    // be removed.
                    EventWaitHandleAccessRule rule =
                        new EventWaitHandleAccessRule(user,
                            EventWaitHandleRights.Synchronize |
                            EventWaitHandleRights.Modify,
                            AccessControlType.Deny);
                    ewhSec.RemoveAccessRule(rule);

                    // Now grant the user the correct rights.
                    // 
                    rule = new EventWaitHandleAccessRule(user,
                        EventWaitHandleRights.Synchronize |
                        EventWaitHandleRights.Modify,
                        AccessControlType.Allow);
                    ewhSec.AddAccessRule(rule);

                    // Update the ACL. This requires
                    // EventWaitHandleRights.ChangePermissions.
                    ewh.SetAccessControl(ewhSec);

                    Console.WriteLine("Updated event security.");

                    // Open the event with (EventWaitHandleRights.Synchronize 
                    // | EventWaitHandleRights.Modify), the rights required
                    // to wait on and signal the event.
                    //
                    ewh = EventWaitHandle.OpenExisting(ewhName);

                }
                catch (UnauthorizedAccessException ex)
                {
                    Console.WriteLine("Unable to change permissions: {0}",
                        ex.Message);
                    return null;
                }
            }
            return ewh;
        }
        public void CreateSharedMemory()
        {
            //Before 
            Console.WriteLine("Wait on the event. Load driver now!!!");
            //You can create custom event to say that your driver is loaded.
            SharedEvent_ready2read.WaitOne();//here we use SharedEvent_ready2read to say that your driver was loaded.
            SharedEvent_ready2read.Reset();
            // Map a view of the file mapping into the address space of the  
            // current process. 
            try
            {
                //Create Shared memory mapped file
                memoryMappedFile = MemoryMappedFile.CreateOrOpen(
                        FullMapName, ViewSize, MemoryMappedFileAccess.ReadWrite);

                //Create View stream
                stream = memoryMappedFile.CreateViewStream();
                Console.WriteLine("Shared memory created.");
            }
            catch (Exception ex)
            {
                Console.WriteLine("CreateSharedMemory failed error: {0}", ex.Message);
            }

        }
        public void ClearPIDCache()
        {
            try
            {
                string Message = "Clearpid";
                byte[] byteArray = Encoding.ASCII.GetBytes(Message);
                stream.Write(byteArray, 0, byteArray.Length);

                SharedEvent_ready2read.WaitOne();

                byte[] buffer = new byte[20]; // choose your string size.
                stream.Position = 0;
                stream.Read(buffer, 0, buffer.Length);
                Console.WriteLine(UnicodeEncoding.ASCII.GetString(buffer).Split('\0')[0]);
                //or
                //Console.WriteLine(new string(Encoding.ASCII.GetChars(buffer)).Split('\0')[0]);
            }
            catch (Exception ex)
            {
                Console.WriteLine("The process throws the error: {0}", ex.Message);
            }

        }

    }
}
