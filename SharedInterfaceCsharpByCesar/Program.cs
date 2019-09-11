using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SharedInterface_by_Cesar
{
    class Program
    {
        /// <summary>
        /// Welcome to Cesar's Shared memory c# Interface Program
        /// Special thx to frankoo for support, and sharedMem release
        ///
        /// First run User Mode (this program)
        /// After run driver
        /// 
        /// If you want manual map driver, check UC how to do that.
        /// Current driver code can be loaded with OSR driver loader,with windowns test mode on, ofc.
        ///
        /// Have Fun!
        /// </summary>
        /// <param name="args"></param>
        static void Main(string[] args)
        {
            SharedInterface sharedInterface = new SharedInterface();
            Console.ForegroundColor = ConsoleColor.Cyan;
            sharedInterface.CreateSharedEvents();
            sharedInterface.CreateSharedMemory();

            sharedInterface.ClearPIDCache();
            Console.ReadLine();
        }
    }
}
