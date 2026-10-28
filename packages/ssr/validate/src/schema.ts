import { HttpError } from '@wardenjs/ssr';

/**
 * The Standard Schema interface (standardschema.dev), implemented by Zod
 * ≥3.24, Valibot, ArkType and others. Declared here so this package has no
 * dependency on any of them.
 */
export interface StandardSchema<Output = unknown> {
  readonly '~standard': {
    readonly version: 1;
    readonly vendor: string;
    readonly validate: (value: unknown) => SchemaResult<Output> | Promise<SchemaResult<Output>>;
    readonly types?: { readonly input: unknown; readonly output: Output } | undefined;
  };
}

type SchemaResult<Output> =
  | { readonly value: Output; readonly issues?: undefined }
  | { readonly issues: readonly SchemaIssue[] };

interface SchemaIssue {
  readonly message: string;
  readonly path?: readonly (PropertyKey | { readonly key: PropertyKey })[] | undefined;
}

export type Infer<S extends StandardSchema> = NonNullable<S['~standard']['types']>['output'];

/**
 * Field path → messages. Messages and paths only, never the received value:
 * echoing input is a reflected-content channel and prints failed passwords
 * into forms and logs.
 */
export function formatIssues(issues: readonly SchemaIssue[]): Record<string, string[]> {
  const out: Record<string, string[]> = {};
  for (const issue of issues) {
    const path = (issue.path ?? []).map((segment) =>
      String(typeof segment === 'object' ? segment.key : segment),
    );
    (out[path.length > 0 ? path.join('.') : '_root'] ??= []).push(issue.message);
  }
  return out;
}

/** 422 with field errors when invalid. */
export async function parse<S extends StandardSchema>(schema: S, value: unknown): Promise<Infer<S>> {
  const result = await schema['~standard'].validate(value);
  if (result.issues) {
    throw new HttpError(422, 'validation_failed', 'The request is invalid.', {
      details: formatIssues(result.issues),
    });
  }
  return result.value;
}
