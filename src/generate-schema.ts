import * as fs from "fs";
import * as path from "path";
import { isDeepStrictEqual } from "util";
import { z } from "zod";
import zodToJsonSchema from "zod-to-json-schema";

export enum Severity {
  info = "info",
  low = "low",
  medium = "medium",
  high = "high",
  critical = "critical",
}

export enum HttpMethod {
  GET = "GET",
  POST = "POST",
  PUT = "PUT",
  DELETE = "DELETE",
  CONNECT = "CONNECT",
  OPTIONS = "OPTIONS",
  TRACE = "TRACE",
  PATCH = "PATCH",
  PURGE = "PURGE",
  Debug = "Debug",
}

export enum AttackType {
  batteringram = "batteringram",
  pitchfork = "pitchfork",
  clusterbomb = "clusterbomb",
  limit = "limit",
}

export type NucleiRequest = {
  method: HttpMethod;
  path: string[];
  id?: string;
  name?: string;
  attack?: AttackType;
  body?: string;
  headers?: Record<string, string>;
  race_count?: number;
  "max-redirects"?: number;
  "pipeline-concurrent-connections"?: number;
  "pipeline-requests-per-connection"?: number;
  threads?: number;
  "max-size"?: number;
  redirects?: boolean;
  pipeline?: boolean;
  unsafe?: boolean;
  race?: boolean;
  "req-condition"?: boolean;
  "iterate-all"?: boolean;
  "skip-variables-check"?: boolean;
  "stop-at-first-match"?: boolean;
  "cookie-reuse"?: boolean;
};

const notEmptyString = z.string().nonempty();

const integer = z.number().int().positive();

const nucleiArrayLike = z.string().regex(/^([a-zA-Z0-9_-]+,?)+$/);

const bool = z.boolean().optional();

const nucleiRequestSchema = z.object({
  method: z
    .nativeEnum(HttpMethod)
    .describe("Http method used for this request"),
  path: z
    .array(z.string().nonempty())
    .nonempty()
    .describe("All paths for the HTTP requests. It supports variables."),
  attack: z
    .nativeEnum(AttackType)
    .optional()
    .describe(
      "Type of payload combinations to perform. 'batteringram' is inserts the same payload into all defined payload positions at once, 'pitchfork' combines multiple payload sets and 'clusterbomb' generates permutations and combinations for all payloads."
    ),
  raw: z.array(notEmptyString).describe("Raw formats for HTTP requests."),
  id: z.string().optional().describe("ID for this request."),
  payloads: z
    .record(z.string())
    .describe(
      "Any payloads for the current request. But you can also provide a file as payload witch will be read on run-time."
    ),
  body: z
    .string()
    .optional()
    .describe("Parameter which contains HTTP request body."),
  headers: z
    .record(z.string())
    .optional()
    .describe("Http headers to send with this request."),
  race_count: integer
    .optional()
    .describe("Number of times to send a request in Race Condition Attack"),
  threads: integer
    .optional()
    .describe(
      "Specify number of threads to use sending requests. This enables Connection Pooling."
    ),
  redirects: bool.describe(
    "Redirects specifies whether redirects should be followed by the HTTP Client. This can be used in conjunction with `max-redirects` to control the HTTP request redirects."
  ),
  pipeline: bool.describe(
    "Pipeline defines if the attack should be performed with HTTP 1.1 Pipelining. All requests must be idempotent (GET/POST). This can be used for race conditions/billions requests"
  ),
  unsafe: bool.describe(
    "Specifies whether to use raw http engine for sending Non RFC-Compliant requests."
  ),
  race: bool.describe(
    "Determines if all the request have to be attemped at the same time (Race Condition). The actual number of requests that will be sent is determined by 'race_count' field."
  ),
  "max-redirects": integer
    .optional()
    .describe("Maximum number of redirects that should be followed"),
  "pipeline-concurrent-connections": integer
    .optional()
    .describe("Number of connections to create during pipelining."),
  "pipeline-requests-per-connection": integer
    .optional()
    .describe("Number of requests to send per connection when pipelining."),
  "max-size": integer
    .optional()
    .describe("Maximum size of http response body to read in bytes."),
  "req-condition": bool.describe(
    "Automatically assigns numbers to requests and preservers their history. This allow matching on them later for multi-request conditions."
  ),
  "iterate-all": bool.describe(
    "Iterates all the values extracted from internal extractors."
  ),
  "skip-variables-check": bool.describe(
    "Skips the check for unresolved variables in request."
  ),
  "stop-at-first-match": bool.describe(
    "Stops the execution of the requests and template as soon as match is found."
  ),
  "cookie-reuse": bool.describe(
    "Setting that enable cookie reuse for all requests defined in raw section."
  ),
});

enum DnsRequestType {
  A = "A",
  NS = "NS",
  DS = "DS",
  CNAME = "SOA",
  PTR = "PTR",
  MX = "TXT",
  AAAA = "AAAA",
}

enum DnsClass {
  inet = "inet",
  csnet = "csnet",
  chaos = "chaos",
  hesiod = "hesiod",
  any = "any",
  none = "none",
}

const nucleiDnsSchema = z.object({
  id: notEmptyString.describe("Id of this request."),
  retries: integer
    .optional()
    .describe("Number of retries for the DNS request."),
  trace: bool.describe("Performs a trace operation for the target."),
  class: z
    .nativeEnum(DnsClass)
    .describe(
      "The class of DNS request. Usually it's enough to just leave it as INET."
    ),
  name: notEmptyString
    .optional()
    .describe(
      "Hostname to make DNS request for. Generally, it is set to {{FQDN}} which is the domain we get from input."
    ),
  recursion: bool.describe(
    "Determines if resolver should recurse all records to get fresh results."
  ),
  type: z.nativeEnum(DnsRequestType).describe("Type of DNS request to make."),
  "trace-max-recursion": integer
    .optional()
    .describe("Number of max recursion allowed for trace operations."),
  resolvers: z
    .array(notEmptyString)
    .optional()
    .describe("Resolvers to use for the dns requests."),
});

const templateInfoSchema = z.object({
  name: notEmptyString.describe(
    "Name of this template. Should be good short summary that identifies what the template does."
  ),
  tags: nucleiArrayLike.describe(
    "Any tags for the template. Multiple values also can be specified separated by comas. 'foo,bar'"
  ),
  author: nucleiArrayLike.describe(
    "Authors of this template. Multiple values also can be specified separated by comas. 'foo,bar'"
  ),
  description: notEmptyString
    .max(2048)
    .optional()
    .describe(
      "Description of this template, you can go in-depth here on what this template actually does."
    ),
  reference: z
    .array(notEmptyString.url())
    .optional()
    .describe("Reference should contain links relevant to this template."),
  severity: z
    .nativeEnum(Severity)
    .optional()
    .describe("Severity level of this template."),
  remediation: z
    .string()
    .optional()
    .describe(
      "Remediation steps, how to mitigate the problem found by this template."
    ),
  classification: z
    .object({
      "cve-id": z
        .string()
        .regex(/^CVE-\d{4}-\d{4,7}$/)
        .describe("CVE id for this template."),
      "cwe-id": z
        .string()
        .regex(/^CWE-[0-9]+$/)
        .describe("CWE id for this template."),
      "cvss-metrics": z.string().describe("CVSS metrics."),
      "cvss-score": integer
        .min(0)
        .max(10)
        .describe("CVSS score for this template."),
    })
    .describe("Information about CVE/CWE classification of this template.")
    .optional(),
});

enum ActionTypeHolder {
  ActionNavigate = "navigate",
  ActionScript = "script",
  ActionClick = "click",
  ActionRightClick = "rightclick",
  ActionTextInput = "text",
  ActionScreenshot = "screenshot",
  ActionTimeInput = "time",
  ActionSelectInput = "select",
  ActionFilesInput = "files",
  ActionWaitLoad = "waitload",
  ActionGetResource = "getresource",
  ActionExtract = "extract",
  ActionAddHeader = "addheader",
  ActionSetHeader = "setheader",
  ActionDeleteHeader = "deleteheader",
  ActionSetBody = "setbody",
  ActionWaitEvent = "waitevent",
  ActionKeyboard = "keyboard",
  ActionDebug = "debug",
  ActionSleep = "sleep",
  ActionWaitVisible = "waitvisible",
  limit = "limit",
}

const headlessSchema = z.object({
  id: notEmptyString.describe("Id of this headless."),
  steps: z
    .array(
      z.object({
        args: z
          .record(z.string())
          .describe(
            "Args contain arguments for the headless action. Reference in https://nuclei.projectdiscovery.io/templating-guide/protocols/headless/"
          ),
        name: notEmptyString.describe(
          "Name is the name assigned to the headless action. This can be used to execute code, for instance in browser DOM using script action."
        ),
        action: z.nativeEnum(ActionTypeHolder).optional(),
      })
    )
    .nonempty(),
});

enum NetworkInputTypeHolder {
  hexType = "hex",
  textType = "text",
  limit = "limit",
}

const networkSchema = z.object({
  id: notEmptyString.describe("Id for network request"),
  address: z
    .array(z.string().nonempty())
    .describe("Host to send network requests to."),
  addresses: z.array(z.object({ address: z.string(), tls: z.boolean() })),
  attack: z
    .nativeEnum(AttackType)
    .describe(
      "Attack is the type of payload combinations to perform. Batteringram is inserts the same payload into all defined payload positions at once, pitchfork combines multiple payload sets and clusterbomb generates permutations and combinations for all payloads."
    ),
  payloads: z
    .record(z.string())
    .describe("Payloads contains any payloads for the current request."),
  inputs: z
    .array(
      z.object({
        data: z.string().describe("The data to send as the input."),
        type: z
          .nativeEnum(NetworkInputTypeHolder)
          .describe("Type is the type of input specified in `data` field"),
        read: integer.describe(
          "Read is the number of bytes to read from socket."
        ),
        name: z
          .string()
          .optional()
          .describe(
            "Name is the optional name of the data read to provide matching on."
          ),
      })
    )
    .describe("Inputs contains inputs for the network socket."),
});

const fileSchema = z.object({
  extensions: z
    .array(notEmptyString)
    .describe("Extensions is the list of extensions to perform matching on."),
  denylist: z
    .array(notEmptyString)
    .describe(
      "ExtensionDenylist is the list of file extensions to deny during matching. By default, it contains some non-interesting extensions that are hardcoded in nuclei."
    ),
  id: z.string().optional().describe("Id of the request"),
  "max-size": integer.describe(
    "MaxSize is the maximum size of the file to run request on. By default, nuclei will process 5 MB files and not go more than that. It can be set to much lower or higher depending on use."
  ),
  "no-recursive": bool.describe(
    "NoRecursive specifies whether to not do recursive checks if folders are provided."
  ),
});

const sslSchema = z.object({
  address: z.string().describe("The address for the request."),
});

const webSocketSchema = z.object({
  address: z.string().describe("The address for the request."),
  headers: z.record(z.string()).describe("Headers for the request."),
  attack: z
    .nativeEnum(AttackType)
    .describe(
      "Type of payload combinations to perform. Sniper is each payload once, pitchfork combines multiple payload sets and clusterbomb generates permutations and combinations for all payloads."
    ),
  payloads: z
    .record(z.string())
    .describe("Any payloads for the current request."),
  inputs: z.array(
    z.object({
      data: z.string().describe("Data is the data to send as the input."),
      name: z
        .string()
        .describe(
          "Name is the optional name of the data read to provide matching on."
        ),
    })
  ),
});

const templateSchema = z.object({
  id: z
    .string()
    .regex(/^([a-zA-Z0-9]+[-_])*[a-zA-Z0-9]+$/)
    .nonempty()
    .describe("ID is the unique id for this template."),
  info: templateInfoSchema.describe(
    "Metadata information about this template."
  ),
  "self-container": bool.describe(
    "Mark requests for this template as self-contained."
  ),
  "stop-at-first-match": bool.describe(
    "Stop execution once first match is found."
  ),
  dns: z
    .array(nucleiDnsSchema)
    .nonempty()
    .describe("DNS contains the dns requests to make in this template."),
  requests: z
    .array(nucleiRequestSchema)
    .nonempty()
    .describe("Requests contains the http requests to make in this template."),
  headless: z
    .array(headlessSchema)
    .nonempty()
    .describe(
      "Headless contains the headless request to make in the template."
    ),
  network: z
    .array(networkSchema)
    .describe("Network contains the network request to make in the template."),
  file: z
    .array(fileSchema)
    .describe("File contains the file request to make in the template."),
  ssl: z
    .array(sslSchema)
    .describe("SSL contains the SSL request to make in the template."),
  websocket: z
    .array(webSocketSchema)
    .describe(
      "Websocket contains the WebSocket request to make in the template."
    ),
});

const jsonSchema: any = zodToJsonSchema(templateSchema, "template");

jsonSchema.title = "Nuclei template schema";
jsonSchema.description = "A Nuclei template definition";

fs.writeFileSync(
  path.resolve(process.cwd(), "service-schema.json"),
  JSON.stringify(jsonSchema, null, 2)
);
