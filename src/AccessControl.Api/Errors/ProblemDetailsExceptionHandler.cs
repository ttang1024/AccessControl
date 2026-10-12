using AccessControl.Application.Errors;
using AccessControl.Domain.Common;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace AccessControl.Api.Errors;

/// <summary>
/// Translates expected failures into RFC 7807 problem responses with a stable <c>code</c>.
/// Anything else falls through to the default 500 handler (logged, no details leaked).
/// </summary>
internal sealed class ProblemDetailsExceptionHandler(IProblemDetailsService problemDetails) : IExceptionHandler
{
    public async ValueTask<bool> TryHandleAsync(HttpContext httpContext, Exception exception, CancellationToken cancellationToken)
    {
        (int Status, string Title, string Code)? mapped = exception switch
        {
            DomainException { Kind: DomainErrorKind.Validation } e => (StatusCodes.Status400BadRequest, "Invalid request", e.Code),
            DomainException e => (StatusCodes.Status409Conflict, "Operation not allowed in current state", e.Code),
            RequestValidationException e => (StatusCodes.Status400BadRequest, "Invalid request", e.Code),
            NotFoundException e => (StatusCodes.Status404NotFound, "Not found", e.Code),
            ForbiddenException e => (StatusCodes.Status403Forbidden, "Forbidden", e.Code),
            PreconditionFailedException e => (StatusCodes.Status412PreconditionFailed, "Precondition failed", e.Code),
            ConflictException e => (StatusCodes.Status409Conflict, "Conflict", e.Code),
            BadHttpRequestException e => (e.StatusCode, "Bad request", "request.malformed"),
            _ => null,
        };

        if (mapped is not { } m)
        {
            return false;
        }

        httpContext.Response.StatusCode = m.Status;
        return await problemDetails.TryWriteAsync(new ProblemDetailsContext
        {
            HttpContext = httpContext,
            Exception = exception,
            ProblemDetails = new ProblemDetails
            {
                Status = m.Status,
                Title = m.Title,
                Detail = exception.Message,
                Extensions = { ["code"] = m.Code },
            },
        }).ConfigureAwait(false);
    }
}
