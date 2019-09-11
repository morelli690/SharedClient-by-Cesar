using System;
using System.Text;
using System.Runtime.InteropServices;
using System.Security;
using System.Security.Permissions;
using Microsoft.Win32.SafeHandles;
using System.Runtime.ConstrainedExecution;
using System.ComponentModel;
     
namespace SharedInterface_by_Cesar
{
    //todo: delete this class.
    /// <summary>
    ///            Delete this class, here only for studies.
    /// This was an attempt to make it native way, isn't working ofc,
    /// but almost*, so
    /// have fun to implement/make work yourself :D
    /// </summary>
    public class NativeAttempt
    {

        // In terminal services: The name can have a "Global\" or "Local\"  
        // prefix to explicitly create the object in the global or session  
        // namespace. The remainder of the name can contain any character except 
        // the backslash character (\). For more information, see:  
        // http://msdn.microsoft.com/en-us/library/aa366537.aspx 
        internal const string MapPrefix = "Global\\";
        internal const string MapName = "SharedMem";//SampleMap
        internal const string FullMapName = MapPrefix + MapName;//_EventName

        // File offset where the view is to begin. 
        internal const uint ViewOffset = 0;

        internal static readonly IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);
        // The number of bytes of a file mapping to map to the view. All bytes of  
        // the view must be within the maximum size of the file mapping object.  
        // If VIEW_SIZE is 0, the mapping extends from the offset (VIEW_OFFSET)  
        // to the end of the file mapping. 
        internal const uint ViewSize = 4096;
        // Unicode string message to be written to the mapped view. Its size in  
        // byte must be less than the view size (VIEW_SIZE).  
        string Message = "Message from the first process.";

        SafeFileMappingHandle hMapFile = null;
        IntPtr pView = IntPtr.Zero;
        SECURITY_ATTRIBUTES sa = new SECURITY_ATTRIBUTES();
        const UInt32 INFINITE = 0xFFFFFFFF;//WaitForSingleObject

        //---------------
        NamedEvent SharedEvent_dataarv;
        NamedEvent SharedEvent_trigger;
        NamedEvent SharedEvent_ready2read;

        public void _createSecuritydesc()
        {
            byte[] SECURITY_WORLD_SID_AUTHORITY = new byte[6] { 0, 0, 0, 0, 0, 1 };
            SidIdentifierAuthority NtAuthority = new SidIdentifierAuthority();
            NtAuthority.Value = SECURITY_WORLD_SID_AUTHORITY;

            IntPtr AuthenticatedUsersSid = IntPtr.Zero;
            //const int AuthenticatedUser = 11;
            const int SECURITY_WORLD_RID = 0;
            // Get the SID for the Authenticated Uses group
            if (!NativeMethods.AllocateAndInitializeSid(ref NtAuthority,
                1,
                SECURITY_WORLD_RID,
                0, 0, 0, 0, 0, 0, 0,
                out AuthenticatedUsersSid))
            {
                NativeMethods.FreeSid(AuthenticatedUsersSid);
                throw new Win32Exception("Failed to AllocateAndInitializeSid");
            }
            // Remember to free the SID when you are done
            //NativeMethods.FreeSid(AuthenticatedUsersSid);

            IntPtr SPECIFIC_RIGHTS_ALL = (IntPtr)0x0000FFFF;
            IntPtr STANDARD_RIGHTS_ALL = (IntPtr)0x001F0000;
            IntPtr SPECIFIC_N_STANDARD_RIGHTS_ALL = (IntPtr)0x001FFFFF;
            uint SET_ACCESS = 2;
            EXPLICIT_ACCESS ea = new EXPLICIT_ACCESS();
            ea.grfAccessPermissions = (uint)RightFlags.SPECIFIC_N_STANDARD_RIGHTS_ALL;
            //(uint)SPECIFIC_N_STANDARD_RIGHTS_ALL;
            ea.grfAccessMode = SET_ACCESS;
            ea.grfInheritance = 0;//NO_INHERITANCE
            ea.Trustee.TrusteeForm = TRUSTEE_FORM.TRUSTEE_IS_SID;//TRUSTEE_IS_SID
            ea.Trustee.TrusteeType = TRUSTEE_TYPE.TRUSTEE_IS_WELL_KNOWN_GROUP;//TRUSTEE_IS_WELL_KNOWN_GROUP
            ea.Trustee.ptstrName = AuthenticatedUsersSid;

            IntPtr NewAclPointer = IntPtr.Zero;
            _ACL NewAcl = new _ACL();
            // Marshal.StructureToPtr(NewAcl, NewAclPointer, true);
            int dwRes = NativeMethods.SetEntriesInAcl(1, ref ea, IntPtr.Zero, out NewAclPointer);
            if (dwRes != 0)
                throw new Win32Exception("Failed to SetEntriesInAcl");

            SECURITY_DESCRIPTOR sec = new SECURITY_DESCRIPTOR();
            Marshal.SizeOf(sec);
            IntPtr pSDlocalAlloc = NativeMethods.LocalAlloc((uint)LMEMFlags.LMEM_FIXED_N_ZEROINIT, (UIntPtr)Marshal.SizeOf(sec));
            //Marshal.PtrToStructure(pSDlocalAlloc, sec);
            if (pSDlocalAlloc == IntPtr.Zero || pSDlocalAlloc == null)
                throw new Win32Exception("Failed to localAlloc");
            if (!NativeMethods.InitializeSecurityDescriptor(out sec, 1))
                throw new Win32Exception("Failed to InitializeSecurityDescriptor");
            if (!NativeMethods.SetSecurityDescriptorDacl(ref sec, true, NewAclPointer, false))
                throw new Win32Exception("Failed to SetSecurityDescriptorDacl");




            //byte[] src = getBytes(sec);
            //IntPtr dest = Marshal.AllocHGlobal(src.Length);
            //Marshal.Copy(src, 0, dest, src.Length);
            //sa.bInheritHandle = 0;
            //sa.nLength = Marshal.SizeOf(sa);
            //sa.lpSecurityDescriptor = dest;
            //Marshal.FreeHGlobal(dest);
            //--------------------

            //byte[] src = getBytes(sec);
            //IntPtr dest = Marshal.AllocHGlobal(src.Length);
            //Marshal.Copy(src, 0, dest, src.Length);
            //gay1
            Marshal.StructureToPtr(sec, pSDlocalAlloc, true);
            sa.bInheritHandle = 0;
            sa.nLength = (uint)Marshal.SizeOf(sa);// its 24 or 816 (8x100 +8(int) +8(int))
            sa.lpSecurityDescriptor = pSDlocalAlloc; // dest;//0x00000193dc8f7420
                                                     //gay1 end

            //Marshal.FreeHGlobal(dest);


            //sa.lpSecurityDescriptor = getBytes(sa);

            //Serialize();
            // Marshal.by(gay, SECURITY_ATTRIBUTES);

            NativeMethods.FreeSid(AuthenticatedUsersSid);
            NativeMethods.LocalFree(pSDlocalAlloc);
        }

        #region enum_struct_security
        //private static unsafe byte[] Serialize()
        //{
        //    SECURITY_ATTRIBUTES[] index = new SECURITY_ATTRIBUTES[1];
        //    var buffer = new byte[Marshal.SizeOf(typeof(SECURITY_ATTRIBUTES)) * index.Length];
        //    fixed (void* d = &buffer[0])
        //    {
        //        fixed (void* s = &index[0])
        //        {
        //            NativeMethods.CopyMemory(d, s, buffer.Length);
        //        }
        //    }
        //    return buffer;
        //}
        byte[] getBytes(SECURITY_DESCRIPTOR str)
        {
            int size = Marshal.SizeOf(str);
            byte[] arr = new byte[size];

            IntPtr ptr = Marshal.AllocHGlobal(size);
            Marshal.StructureToPtr(str, ptr, true);
            Marshal.Copy(ptr, arr, 0, size);
            Marshal.FreeHGlobal(ptr);
            return arr;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct _ACL
        {
            public byte AclRevision;
            public byte Sbz1;
            public ushort AclSize;
            public ushort AceCount;
            public ushort Sbz2;
        }

        [StructLayout(LayoutKind.Sequential)]
        public struct SECURITY_ATTRIBUTES
        {
            public uint nLength;
            //[MarshalAs(UnmanagedType.ByValTStr, SizeConst = 100)]
            public IntPtr lpSecurityDescriptor;
            public uint bInheritHandle;
        }

        public enum EVENT_TYPE
        {
            NotificationEvent = 0,
            SynchronizationEvent = 1
        }

        [StructLayoutAttribute(LayoutKind.Sequential)]
        public struct SECURITY_DESCRIPTOR
        {
            public byte revision;
            public byte size;
            public short control;
            public IntPtr owner;
            public IntPtr group;
            public IntPtr sacl;
            public IntPtr dacl;
        }
        [Flags]
        public enum RightFlags
        {
            SPECIFIC_RIGHTS_ALL = 0x0000FFFF,
            STANDARD_RIGHTS_ALL = 0x001F0000,
            SPECIFIC_N_STANDARD_RIGHTS_ALL = SPECIFIC_RIGHTS_ALL | STANDARD_RIGHTS_ALL
        }
        [Flags]
        public enum LMEMFlags
        {
            LMEM_FIXED = 0x0000,
            LMEM_ZEROINIT = 0x0040,
            LMEM_FIXED_N_ZEROINIT = LMEM_FIXED | LMEM_ZEROINIT
        }
        public enum MULTIPLE_TRUSTEE_OPERATION
        {
            NO_MULTIPLE_TRUSTEE,
            TRUSTEE_IS_IMPERSONATE
        }

        public enum TRUSTEE_FORM
        {
            TRUSTEE_IS_SID,
            TRUSTEE_IS_NAME,
            TRUSTEE_BAD_FORM,
            TRUSTEE_IS_OBJECTS_AND_SID,
            TRUSTEE_IS_OBJECTS_AND_NAME
        }

        public enum TRUSTEE_TYPE
        {
            TRUSTEE_IS_UNKNOWN,
            TRUSTEE_IS_USER,
            TRUSTEE_IS_GROUP,
            TRUSTEE_IS_DOMAIN,
            TRUSTEE_IS_ALIAS,
            TRUSTEE_IS_WELL_KNOWN_GROUP,
            TRUSTEE_IS_DELETED,
            TRUSTEE_IS_INVALID,
            TRUSTEE_IS_COMPUTER
        }

        //Platform independent (32 & 64 bit) - use Pack = 0 for both platforms. IntPtr works as well.
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto, Pack = 0)]
        public struct TRUSTEE : IDisposable
        {
            public IntPtr pMultipleTrustee;
            public MULTIPLE_TRUSTEE_OPERATION MultipleTrusteeOperation;
            public TRUSTEE_FORM TrusteeForm;
            public TRUSTEE_TYPE TrusteeType;
            public IntPtr ptstrName;

            void IDisposable.Dispose()
            {
                if (ptstrName != IntPtr.Zero) Marshal.Release(ptstrName);
            }

            public string Name { get { return Marshal.PtrToStringAuto(ptstrName); } }//useless once i need to set it
        }
        [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Auto, Pack = 0)] //Platform independent 32 & 64 bit - use Pack = 0 for both platforms
        public struct EXPLICIT_ACCESS
        {
            public uint grfAccessPermissions;
            public uint grfAccessMode;
            public uint grfInheritance;
            public TRUSTEE Trustee;
        }

        #endregion

        public void ClearPIDCache()
        {
            IntPtr pView = IntPtr.Zero;
            // Map a view of the file mapping into the address space of the  
            // current process. 
            try
            {
                // Try to open the named file mapping. 
                hMapFile = NativeMethod.OpenFileMapping(
                    FileMapAccess.FILE_MAP_WRITE,    // Read access 
                    false,                          // Do not inherit the name 
                    FullMapName                     // File mapping name 
                    );
                if (hMapFile.IsInvalid)
                {
                    throw new Win32Exception();
                }

                Console.WriteLine("The file mapping ({0}) is opened", FullMapName);

                pView = NativeMethod.MapViewOfFile(
                hMapFile,                       // Handle of the map object 
                FileMapAccess.FILE_MAP_WRITE, // Read and write access 
                0,                              // High-order DWORD of file offset  
                ViewOffset,                     // Low-order DWORD of file offset 
                ViewSize                        // Byte# to map to the view 
                );

                if (pView == IntPtr.Zero)
                {
                    throw new Win32Exception("Failed to write Clearpid request");
                }

                Console.WriteLine("The file view is mapped");

                // Prepare a message to be written to the view. Append '\0' to  
                // mark the end of the string when it is marshaled to the native  
                // memory. 
                Message = "Clearpid";
                byte[] bMessage = Encoding.ASCII.GetBytes(Message + '\0');

                // Write the message to the view. 
                Marshal.Copy(bMessage, 0, pView, bMessage.Length);
                WaitForSingleObject(SharedEvent_ready2read._Handle, (uint)INFINITE);
                Console.WriteLine("This message is written to the view:\n\"{0}\"",
                    Message);

                // Wait to clean up resources and stop the process. 
                Console.WriteLine("Press ENTER to clean up resources and quit");
                Console.ReadLine();

            }
            catch (Exception ex)
            {
                Console.WriteLine("The process throws the error: {0}", ex.Message);
            }
            finally
            {
                if (hMapFile != null)
                {
                    if (pView != IntPtr.Zero)
                    {
                        // Unmap the file view. 
                        NativeMethod.UnmapViewOfFile(pView);
                        pView = IntPtr.Zero;
                    }
                    // Close the file mapping object. 
                    hMapFile.Close();
                    hMapFile = null;
                }
            }

            //SharedEvent_ready2read = CreateEventA(&sa, TRUE, FALSE, "Global\\ReadyRead");
            IntPtr handle = IntPtr.Zero;//SharedEvent_ready2read
            WaitForSingleObject(SharedEvent_ready2read._Handle, (uint)INFINITE);
            //read
            try
            {
                // Try to open the named file mapping. 
                hMapFile = NativeMethod.OpenFileMapping(
                    FileMapAccess.FILE_MAP_READ,    // Read access 
                    false,                          // Do not inherit the name 
                    FullMapName                     // File mapping name 
                    );
                if (hMapFile.IsInvalid)
                {
                    throw new Win32Exception();
                }

                Console.WriteLine("The file mapping ({0}) is opened", FullMapName);

                // Map a view of the file mapping into the address space of the  
                // current process. 
                pView = NativeMethod.MapViewOfFile(
                    hMapFile,                       // Handle of the map object 
                    FileMapAccess.FILE_MAP_READ,    // Read access 
                    0,                              // High-order DWORD of file offset  
                    ViewOffset,                     // Low-order DWORD of file offset 
                    ViewSize                        // Byte# to map to view 
                    );

                if (pView == IntPtr.Zero)
                {
                    throw new Win32Exception("Failed to read Clearpid answer");
                }

                Console.WriteLine("The file view is mapped");

                // Read and display the content in the view. 
                string message = Marshal.PtrToStringAnsi(pView);
                Console.WriteLine("Read from the file mapping:\n\"{0}\"", message);

                // Wait to clean up resources and stop the process. 
                Console.WriteLine("Press ENTER to clean up resources and quit");
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine("The process throws the error: {0}", ex.Message);
            }
            finally
            {
                if (hMapFile != null)
                {
                    if (pView != IntPtr.Zero)
                    {
                        // Unmap the file view. 
                        NativeMethod.UnmapViewOfFile(pView);
                        pView = IntPtr.Zero;
                    }
                    // Close the file mapping object. 
                    hMapFile.Close();
                    hMapFile = null;
                }
            }
        }
        public void ClearMmunloadedDrivers()
        {
            IntPtr pView = IntPtr.Zero;
            // Map a view of the file mapping into the address space of the  
            // current process. 
            try
            {
                pView = NativeMethod.MapViewOfFile(
                hMapFile,                       // Handle of the map object 
                FileMapAccess.FILE_MAP_WRITE, // Read and write access 
                0,                              // High-order DWORD of file offset  
                ViewOffset,                     // Low-order DWORD of file offset 
                ViewSize                        // Byte# to map to the view 
                );

                if (pView == IntPtr.Zero)
                {
                    throw new Win32Exception("Failed to write Clearmm request");
                }

                Console.WriteLine("The file view is mapped");

                // Prepare a message to be written to the view. Append '\0' to  
                // mark the end of the string when it is marshaled to the native  
                // memory. 
                Message = "Clearmm";
                byte[] bMessage = Encoding.Unicode.GetBytes(Message + '\0');

                // Write the message to the view. 
                Marshal.Copy(bMessage, 0, pView, bMessage.Length);

                Console.WriteLine("This message is written to the view:\n\"{0}\"",
                    Message);

                // Wait to clean up resources and stop the process. 
                Console.Write("Press ENTER to clean up resources and quit");
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine("The process throws the error: {0}", ex.Message);
            }
            finally
            {
                if (hMapFile != null)
                {
                    if (pView != IntPtr.Zero)
                    {
                        // Unmap the file view. 
                        NativeMethod.UnmapViewOfFile(pView);
                        pView = IntPtr.Zero;
                    }
                    // Close the file mapping object. 
                    //hMapFile.Close();
                    //hMapFile = null;
                }
            }

            //SharedEvent_ready2read = CreateEventA(&sa, TRUE, FALSE, "Global\\ReadyRead");
            IntPtr handle = IntPtr.Zero;//SharedEvent_ready2read
            WaitForSingleObject(handle, (uint)INFINITE);
            //read
            try
            {
                // Try to open the named file mapping. 
                hMapFile = NativeMethod.OpenFileMapping(
                    FileMapAccess.FILE_MAP_READ,    // Read access 
                    false,                          // Do not inherit the name 
                    FullMapName                     // File mapping name 
                    );
                if (hMapFile.IsInvalid)
                {
                    throw new Win32Exception();
                }

                Console.WriteLine("The file mapping ({0}) is opened", FullMapName);

                // Map a view of the file mapping into the address space of the  
                // current process. 
                pView = NativeMethod.MapViewOfFile(
                    hMapFile,                       // Handle of the map object 
                    FileMapAccess.FILE_MAP_READ,    // Read access 
                    0,                              // High-order DWORD of file offset  
                    ViewOffset,                     // Low-order DWORD of file offset 
                    ViewSize                        // Byte# to map to view 
                    );

                if (pView == IntPtr.Zero)
                {
                    throw new Win32Exception("Failed to read Clearmm answer");
                }

                Console.WriteLine("The file view is mapped");

                // Read and display the content in the view. 
                string message = Marshal.PtrToStringUni(pView);
                Console.WriteLine("Read from the file mapping:\n\"{0}\"", message);

                // Wait to clean up resources and stop the process. 
                Console.Write("Press ENTER to clean up resources and quit");
                Console.ReadLine();
            }
            catch (Exception ex)
            {
                Console.WriteLine("The process throws the error: {0}", ex.Message);
            }
            finally
            {
                if (hMapFile != null)
                {
                    if (pView != IntPtr.Zero)
                    {
                        // Unmap the file view. 
                        NativeMethod.UnmapViewOfFile(pView);
                        pView = IntPtr.Zero;
                    }
                    // Close the file mapping object. 
                    //hMapFile.Close();
                    //hMapFile = null;
                }
            }
        }

        public void CreateSharedEvents()
        {
            IntPtr pnt = Marshal.AllocHGlobal(Marshal.SizeOf(sa));
            Marshal.StructureToPtr(sa, pnt, false);
            SharedEvent_dataarv = new NamedEvent(sa.lpSecurityDescriptor, "Global\\DataArrived", true);
            SharedEvent_trigger = new NamedEvent(pnt, "Global\\trigger", true);
            SharedEvent_ready2read = new NamedEvent(pnt, "Global\\ReadyRead", true);
            Marshal.FreeHGlobal(pnt);
            //NamedEvent SharedEvent_trigger = new NamedEvent(pnt,"Global\\SharedMem",true);
            //SharedEvent_dataarv = CreateEventA(&sa, TRUE, FALSE, "Global\\DataArrived");
        }
        public partial class NamedEvent
        {

            public string _EventName;
            public IntPtr _Handle;
            public IntPtr _Attributes = IntPtr.Zero;
            public bool _ManualReset;
            public bool _InitialState;
            /// <summary>
            /// Create a NamedEvent object with the name of the event and the auto reset property,
            /// assuming an initial state of reset.
            /// </summary>
            public NamedEvent(IntPtr _Attributes, string EventName, bool ManualReset)
            {
                _EventName = EventName;
                _ManualReset = ManualReset;
                _InitialState = false;
                _Handle = CreateEvent(_Attributes, _ManualReset, _InitialState, _EventName);
                //_Handle = CreateEventExW(IntPtr.Zero, _EventName,1, 0x1F0003);
                if (_Handle == IntPtr.Zero)
                    Console.WriteLine("Shit goes wrong with: {0}", _EventName);
                //CloseHandle(_Handle); close after use it, call when exit program.
            }

            /// <summary>
            /// Wait for the event to signal to a maximum period of TimeoutInSecs total seconds.
            /// Returns true if the event signaled, false if timeout occurred.
            /// </summary>
            public bool Wait(int TimeoutInSecs)
            {
                int rc = WaitForSingleObject(_Handle, TimeoutInSecs * 1000);
                return rc == 0;
            }

            /// <summary>
            /// Pulse the named event, which results in a single waiting thread to exit the Wait method.
            /// </summary>
            public bool Pulse()
            {
                PulseEvent(_Handle);
                return _Handle != IntPtr.Zero;
            }

            /// <summary>
            /// Set the named event to a signaled state. The Wait() method will not block any
            /// thread as long as the event is in a signaled state.
            /// </summary>
            public void Set()
            {
                SetEvent(_Handle);
            }

            /// <summary>
            /// Reset the named event to a non signaled state. The Wait() method will block
            /// any thread that enters it as long as the event is in a non signaled state.
            /// </summary>
            public void Reset()
            {
                ResetEvent(_Handle);
            }


            [DllImport("kernel32.dll")]
            static extern IntPtr CreateEvent(IntPtr lpEventAttributes, bool bManualReset, bool bInitialState, string lpName);

            [DllImport("kernel32.dll")]
            static extern IntPtr CreateEventExW(IntPtr lpEventAttributes, string lpName, Int32 dwFlags, Int32 dwDesiredAccess);

            [DllImport("kernel32.dll", SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            static extern bool CloseHandle(IntPtr hObject);

            [DllImport("kernel32.dll")]
            static extern bool SetEvent(IntPtr hEvent);


            [DllImport("kernel32.dll")]
            static extern bool ResetEvent(IntPtr hEvent);

            [DllImport("kernel32.dll")]
            static extern bool PulseEvent(IntPtr hEvent);

            [DllImport("kernel32", SetLastError = true, ExactSpelling = true)]
            internal static extern Int32 WaitForSingleObject(IntPtr handle, Int32 milliseconds);

        }


        //shared shit
        [System.Runtime.InteropServices.StructLayoutAttribute(System.Runtime.InteropServices.LayoutKind.Sequential)]
        public struct SidIdentifierAuthority
        {

            /// BYTE[6]
            [System.Runtime.InteropServices.MarshalAsAttribute(
                System.Runtime.InteropServices.UnmanagedType.ByValArray,
                SizeConst = 6,
                ArraySubType = System.Runtime.InteropServices.UnmanagedType.I1)]
            public byte[] Value;
        }

        public partial class NativeMethods
        {

            /// Return Type: BOOL->int
            ///pIdentifierAuthority: PSID_IDENTIFIER_AUTHORITY->_SID_IDENTIFIER_AUTHORITY*
            ///nSubAuthorityCount: BYTE->unsigned char
            ///nSubAuthority0: DWORD->unsigned int
            ///nSubAuthority1: DWORD->unsigned int
            ///nSubAuthority2: DWORD->unsigned int
            ///nSubAuthority3: DWORD->unsigned int
            ///nSubAuthority4: DWORD->unsigned int
            ///nSubAuthority5: DWORD->unsigned int
            ///nSubAuthority6: DWORD->unsigned int
            ///nSubAuthority7: DWORD->unsigned int
            ///pSid: PSID*
            [System.Runtime.InteropServices.DllImportAttribute("advapi32.dll", EntryPoint = "AllocateAndInitializeSid")]
            [return: System.Runtime.InteropServices.MarshalAsAttribute(System.Runtime.InteropServices.UnmanagedType.Bool)]
            public static extern bool AllocateAndInitializeSid(
                [System.Runtime.InteropServices.InAttribute()]
            ref SidIdentifierAuthority pIdentifierAuthority,
                byte nSubAuthorityCount,
                uint nSubAuthority0,
                uint nSubAuthority1,
                uint nSubAuthority2,
                uint nSubAuthority3,
                uint nSubAuthority4,
                uint nSubAuthority5,
                uint nSubAuthority6,
                uint nSubAuthority7,
                out System.IntPtr pSid);

            #region create security part
            //create security part
            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern int SetEntriesInAcl(
             int cCountOfExplicitEntries,
             ref EXPLICIT_ACCESS pListOfExplicitEntries,
             IntPtr OldAcl,
             out IntPtr NewAcl);

            [DllImport("advapi32.dll")]
            public static extern IntPtr FreeSid(IntPtr pSid);
            [Flags]
            public enum LocalMemoryFlags
            {
                LMEM_FIXED = 0x0000,
                LMEM_MOVEABLE = 0x0002,
                LMEM_NOCOMPACT = 0x0010,
                LMEM_NODISCARD = 0x0020,
                LMEM_ZEROINIT = 0x0040,
                LMEM_MODIFY = 0x0080,
                LMEM_DISCARDABLE = 0x0F00,
                LMEM_VALID_FLAGS = 0x0F72,
                LMEM_INVALID_HANDLE = 0x8000,
                LHND = (LMEM_MOVEABLE | LMEM_ZEROINIT),
                LPTR = (LMEM_FIXED | LMEM_ZEROINIT),
                NONZEROLHND = (LMEM_MOVEABLE),
                NONZEROLPTR = (LMEM_FIXED)
            }

            [DllImport("kernel32.dll")]
            public static extern IntPtr LocalAlloc(uint uFlags, UIntPtr uBytes);
            [DllImport("kernel32.dll", SetLastError = true)]
            public static extern IntPtr LocalFree(IntPtr hMem);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool InitializeSecurityDescriptor(out SECURITY_DESCRIPTOR SecurityDescriptor, uint dwRevision);

            [DllImport("advapi32.dll", SetLastError = true)]
            public static extern bool SetSecurityDescriptorDacl(ref SECURITY_DESCRIPTOR sd, bool daclPresent, IntPtr dacl, bool daclDefaulted);

            [DllImport("kernel32.dll", EntryPoint = "CopyMemory", SetLastError = false)]
            public static unsafe extern void CopyMemory(void* dest, void* src, int count);

            [DllImport("kernel32.dll")]
            public static extern bool CreateDirectory(string lpPathName, SECURITY_ATTRIBUTES lpSecurityAttributes);
            #endregion
        }


        #region Native API Signatures and Types 

        /// <summary> 
        /// Memory Protection Constants 
        /// http://msdn.microsoft.com/en-us/library/aa366786.aspx 
        /// </summary> 
        [Flags]
        public enum FileProtection : uint
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400,
            SEC_FILE = 0x800000,
            SEC_IMAGE = 0x1000000,
            SEC_RESERVE = 0x4000000,
            SEC_COMMIT = 0x8000000,
            SEC_NOCACHE = 0x10000000
        }


        /// <summary> 
        /// Access rights for file mapping objects 
        /// http://msdn.microsoft.com/en-us/library/aa366559.aspx 
        /// </summary> 
        [Flags]
        public enum FileMapAccess
        {
            FILE_MAP_COPY = 0x0001,
            FILE_MAP_WRITE = 0x0002,
            FILE_MAP_READ = 0x0004,
            FILE_MAP_ALL_ACCESS = 0x000F001F
        }


        /// <summary> 
        /// Represents a wrapper class for a file mapping handle.  
        /// </summary> 
        [SuppressUnmanagedCodeSecurity,
        HostProtection(SecurityAction.LinkDemand, MayLeakOnAbort = true)]
        internal sealed class SafeFileMappingHandle : SafeHandleZeroOrMinusOneIsInvalid
        {
            [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
            private SafeFileMappingHandle()
                : base(true)
            {
            }

            [SecurityPermission(SecurityAction.LinkDemand, UnmanagedCode = true)]
            public SafeFileMappingHandle(IntPtr handle, bool ownsHandle)
                : base(ownsHandle)
            {
                base.SetHandle(handle);
            }

            [ReliabilityContract(Consistency.WillNotCorruptState, Cer.Success),
            DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            private static extern bool CloseHandle(IntPtr handle);

            protected override bool ReleaseHandle()
            {
                return CloseHandle(base.handle);
            }
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
        ////////// Interop information for managing a Win32 event ////////////

        /// <summary> 
        /// The class exposes Windows APIs used in this code sample. 
        /// </summary> 
        [SuppressUnmanagedCodeSecurity]
        internal class NativeMethod
        {
            /// <summary> 
            /// Opens a named file mapping object. 
            /// </summary> 
            /// <param name="dwDesiredAccess"> 
            /// The access to the file mapping object. This access is checked against  
            /// any security descriptor on the target file mapping object. 
            /// </param> 
            /// <param name="bInheritHandle"> 
            /// If this parameter is TRUE, a process created by the CreateProcess  
            /// function can inherit the handle; otherwise, the handle cannot be  
            /// inherited. 
            /// </param> 
            /// <param name="lpName"> 
            /// The name of the file mapping object to be opened. 
            /// </param> 
            /// <returns> 
            /// If the function succeeds, the return value is an open handle to the  
            /// specified file mapping object. 
            /// </returns> 
            [DllImport("kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern SafeFileMappingHandle OpenFileMapping(
                FileMapAccess dwDesiredAccess, bool bInheritHandle, string lpName);


            /// <summary> 
            /// Maps a view of a file mapping into the address space of a calling 
            /// process. 
            /// </summary> 
            /// <param name="hFileMappingObject"> 
            /// A handle to a file mapping object. The CreateFileMapping and  
            /// OpenFileMapping functions return this handle. 
            /// </param> 
            /// <param name="dwDesiredAccess"> 
            /// The type of access to a file mapping object, which determines the  
            /// protection of the pages. 
            /// </param> 
            /// <param name="dwFileOffsetHigh"> 
            /// A high-order DWORD of the file offset where the view begins. 
            /// </param> 
            /// <param name="dwFileOffsetLow"> 
            /// A low-order DWORD of the file offset where the view is to begin. 
            /// </param> 
            /// <param name="dwNumberOfBytesToMap"> 
            /// The number of bytes of a file mapping to map to the view. All bytes  
            /// must be within the maximum size specified by CreateFileMapping. 
            /// </param> 
            /// <returns> 
            /// If the function succeeds, the return value is the starting address  
            /// of the mapped view. 
            /// </returns> 
            [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            public static extern IntPtr MapViewOfFile(
                SafeFileMappingHandle hFileMappingObject,
                FileMapAccess dwDesiredAccess,
                uint dwFileOffsetHigh,
                uint dwFileOffsetLow,
                uint dwNumberOfBytesToMap);


            /// <summary> 
            /// Unmaps a mapped view of a file from the calling process's address  
            /// space. 
            /// </summary> 
            /// <param name="lpBaseAddress"> 
            /// A pointer to the base address of the mapped view of a file that  
            /// is to be unmapped. 
            /// </param> 
            /// <returns></returns> 
            [DllImport("Kernel32.dll", CharSet = CharSet.Auto, SetLastError = true)]
            [return: MarshalAs(UnmanagedType.Bool)]
            public static extern bool UnmapViewOfFile(IntPtr lpBaseAddress);


            //----------------------------------------------------------------------------------------------------------
            /// <summary> 
            /// Creates or opens a named or unnamed file mapping object for a  
            /// specified file. 
            /// </summary> 
            /// <param name="hFile"> 
            /// A handle to the file from which to create a file mapping object. 
            /// </param> 
            /// <param name="lpAttributes"> 
            /// A pointer to a SECURITY_ATTRIBUTES structure that determines  
            /// whether a returned handle can be inherited by child processes. 
            /// </param> 
            /// <param name="flProtect"> 
            /// Specifies the page protection of the file mapping object. All  
            /// mapped views of the object must be compatible with this  
            /// protection. 
            /// </param> 
            /// <param name="dwMaximumSizeHigh"> 
            /// The high-order DWORD of the maximum size of the file mapping  
            /// object. 
            /// </param> 
            /// <param name="dwMaximumSizeLow"> 
            /// The low-order DWORD of the maximum size of the file mapping  
            /// object. 
            /// </param> 
            /// <param name="lpName"> 
            /// The name of the file mapping object. 
            /// </param> 
            /// <returns> 
            /// If the function succeeds, the return value is a handle to the  
            /// newly created file mapping object. 
            /// </returns> 
            [DllImport("Kernel32.dll", SetLastError = true)]
            public static extern SafeFileMappingHandle CreateFileMapping(
                IntPtr hFile,
                IntPtr lpAttributes,
                FileProtection flProtect,
                uint dwMaximumSizeHigh,
                uint dwMaximumSizeLow,
                string lpName);


        }

        #endregion
    }

}
