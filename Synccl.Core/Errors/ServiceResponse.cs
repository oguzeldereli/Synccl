using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace Synccl.Core.Errors
{
    public class ServiceResponse
    {
        public bool Success { get; set; }
        public string? ErrorMessage { get; set; }
        public static ServiceResponse Ok()
        {
            return new ServiceResponse { Success = true };
        }
        public static ServiceResponse Fail(string errorMessage)
        {
            return new ServiceResponse { Success = false, ErrorMessage = errorMessage };
        }
        public bool IsFailure => !Success || ErrorMessage != null;
    }

    public class ServiceResponse<T> : ServiceResponse
    {
        public T? Data { get; set; }
        public static ServiceResponse<T> Ok(T data)
        {
            return new ServiceResponse<T> { Success = true, Data = data };
        }
        public new static ServiceResponse<T> Fail(string errorMessage)
        {
            return new ServiceResponse<T> { Success = false, ErrorMessage = errorMessage };
        }
        public new bool IsFailure => !Success || ErrorMessage != null || Data == null;
    }
}
