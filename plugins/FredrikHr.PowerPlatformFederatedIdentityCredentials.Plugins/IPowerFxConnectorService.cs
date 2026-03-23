using System.Reflection;

using FredrikHr.PowerPlatformFederatedIdentityCredentials.Plugins;

#pragma warning disable IDE0130 // Namespace does not match folder structure
namespace Microsoft.Xrm.Sdk;
#pragma warning restore IDE0130 // Namespace does not match folder structure

internal readonly record struct IPowerFxConnectorService
{

    internal static Type TypeReference { get; } = Type.GetType(
        "Microsoft.Xrm.Sdk.IPowerFxConnectorService" + ", " +
        "Microsoft.Xrm.Kernel.Contracts.Internal, Culture=neutral, PublicKeyToken=31bf3856ad364e35",
        throwOnError: true
        );

    internal readonly object Target { get; }

    internal static IPowerFxConnectorService Wrap(object target) => new(target);

    private IPowerFxConnectorService(object target)
    {
        _ = target ?? throw new ArgumentNullException(nameof(target));
        if (!TypeReference.IsAssignableFrom(target.GetType()))
            throw new InvalidCastException();
        Target = target;
    }

    internal static IPowerFxConnectorService FromServiceProvider(
        IServiceProvider serviceProvider
        )
    {
        object callbackService = serviceProvider.GetSandboxCallbackService();
        Type implementationType = Type.GetType(
            "Microsoft.CDSRuntime.SandboxWorker.PowerFxConnectorServiceProvider" + ", " +
            "Microsoft.CDSRuntime.SandboxWorker, PublicKeyToken=31bf3856ad364e35",
            throwOnError: true
            );
        object target = Activator.CreateInstance(
            implementationType,
            callbackService
            );
        return Wrap(target);
    }

    public readonly SafeHttpResponse GetResponseUsingOboToken(
        SafeHttpRequestMessage safeHttpRequestMessage
        ) => SafeHttpResponse.Wrap(TypeReference.InvokeMember(
            nameof(GetResponseUsingOboToken),
            BindingFlags.Instance |
            BindingFlags.Public |
            BindingFlags.InvokeMethod,
            Type.DefaultBinder,
            Target,
            [safeHttpRequestMessage.Target],
            System.Globalization.CultureInfo.InvariantCulture
            ));

    public readonly SafeHttpResponse GetResponseUsingManagedIdentity(
        SafeHttpRequestMessage safeHttpRequestMessage
        ) => SafeHttpResponse.Wrap(TypeReference.InvokeMember(
            nameof(GetResponseUsingManagedIdentity),
            BindingFlags.Instance |
            BindingFlags.Public |
            BindingFlags.InvokeMethod,
            Type.DefaultBinder,
            Target,
            [safeHttpRequestMessage.Target],
            System.Globalization.CultureInfo.InvariantCulture
            ));
}

internal readonly record struct SafeHttpRequestMessage
{
    private const string FullTypeName = "Microsoft.Xrm.Sdk.SafeHttpRequestMessage";
    private const string AssemblyName = "Microsoft.Xrm.Kernel.Contracts.Internal, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
    internal static Type TypeReference { get; } = Type.GetType(
        FullTypeName + ", " +
        AssemblyName,
        throwOnError: true
        );

    public readonly object Target { get; }

    public static SafeHttpRequestMessage Wrap(object target) => new(target);

    private SafeHttpRequestMessage(object target)
    {
        _ = target ?? throw new ArgumentNullException(nameof(target));
        if (!TypeReference.IsAssignableFrom(target.GetType()))
            throw new InvalidCastException();
        Target = target;
    }

    internal SafeHttpRequestMessage(
        string url,
        string method,
        IReadOnlyDictionary<string, string> headers,
        IReadOnlyDictionary<string, string> contentHeaders,
        string body
        ) : this(Activator.CreateInstance(
            TypeReference,
            url,
            method,
            headers,
            contentHeaders,
            body
        )) { }

    public readonly string Url => (string)((dynamic)Target).Url;
    public readonly string Method => (string)((dynamic)Target).Method;
    public readonly IReadOnlyDictionary<string, string> Headers =>
        (IReadOnlyDictionary<string, string>)((dynamic)Target).Headers;
    public readonly IReadOnlyDictionary<string, string> ContentHeaders =>
        (IReadOnlyDictionary<string, string>)((dynamic)Target).ContentHeaders;
    public readonly string Body => (string)((dynamic)Target).Body;
}

internal readonly record struct SafeHttpResponse
{
    private const string FullTypeName = "Microsoft.Xrm.Sdk.SafeHttpResponse";
    private const string AssemblyName = "Microsoft.Xrm.Kernel.Contracts.Internal, Culture=neutral, PublicKeyToken=31bf3856ad364e35";
    internal static Type TypeReference { get; } = Type.GetType(
        FullTypeName + ", " +
        AssemblyName,
        throwOnError: true
        );

    public readonly object Target { get; }

    public static SafeHttpResponse Wrap(object target) => new(target);

    private SafeHttpResponse(object target)
    {
        _ = target ?? throw new ArgumentNullException(nameof(target));
        if (!TypeReference.IsAssignableFrom(target.GetType()))
            throw new InvalidCastException();
        Target = target;
    }

    internal SafeHttpResponse(
        int statusCode,
        IReadOnlyDictionary<string, string> headers,
        IReadOnlyDictionary<string, string> contentHeaders,
        string body
        ) : this(Activator.CreateInstance(
            TypeReference,
            statusCode,
            headers,
            contentHeaders,
            body
        )) { }

    public readonly int StatusCode =>
        (int)((dynamic)Target).StatusCode;
    public readonly IReadOnlyDictionary<string, string> Headers =>
        (IReadOnlyDictionary<string, string>)((dynamic)Target).Headers;
    public readonly IReadOnlyDictionary<string, string> ContentHeaders =>
        (IReadOnlyDictionary<string, string>)((dynamic)Target).ContentHeaders;
    public readonly string Body => (string)((dynamic)Target).Body;
}