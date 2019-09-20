using System;

namespace SharedMemory_CLI
{
    class Program
    {
        static void Main(string[] args)
        {
            SharedMemory sharedMemory = new SharedMemory();

            sharedMemory.ClearPIDDBCacheTable();
            sharedMemory.ClearMMUnloadedDrivers();

            while (true)
            {
                // Infinite loop for read / write.
            }
        }
    }
}
