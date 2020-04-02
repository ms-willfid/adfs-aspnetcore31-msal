using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace SampleApp.Models
{
    public class CustomClaimTypes
    {
        public const string Name = "name";
        public const string UserPrincipalName = "http://schemas.xmlsoap.org/ws/2005/05/identity/claims/upn";


        public const string ObjectId = "http://schemas.microsoft.com/identity/claims/objectidentifier";
        public const string Oid = "oid";
        public const string PreferredUserName = "preferred_username";

        public const string HomeTenantId = "http://schemas.microsoft.com/identity/claims/identityprovider";
        public const string TenantId = "http://schemas.microsoft.com/identity/claims/tenantid";
        public const string Tid = "tid";

        public const string ClientInfo = "client_info";
        public const string UniqueObjectIdentifier = "utid";
        // Older scope claim
        public const string Scope = "http://schemas.microsoft.com/identity/claims/scope";
        // Newer scope claim
        public const string Scp = "scp";
        public const string Roles = "roles";
        public const string Role = "http://schemas.microsoft.com/ws/2008/06/identity/claims/role";
        public const string Sub = "sub";

        // Policy claims
        public const string Acr = "acr";
        public const string UserFlow = "http://schemas.microsoft.com/claims/authnclassreference";
        public const string Tfp = "tfp";
    }
}
