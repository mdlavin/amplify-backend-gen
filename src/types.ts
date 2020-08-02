export class ResourceOutputReference {
  constructor(
    public readonly category: string,
    public readonly resource: string,
    public readonly output: string
  ) {}
}

export type ApiTable = {
  readonly type: "apiTable";
  readonly apiName: string;
  readonly tableName: string;
};

export const apiTableOutputReference = (
  table: ApiTable
): ResourceOutputReference =>
  new ResourceOutputReference("api", table.apiName, "GraphQLAPIIdOutput");

export class Parameter {
  constructor(
    public readonly name: string,
    public readonly defaultValue?: string
  ) {}
}

export type Table = ApiTable;

export type UserPool = {
  readonly type: "amplifyAuthUserPool";
  readonly authName: string;
};

export const userPoolOutputReference = (
  userPool: UserPool,
  output: "UserPoolId"
): ResourceOutputReference =>
  new ResourceOutputReference("auth", userPool.authName, output);

export type TableAction = "UpdateItem" | "ReadItem";
export type TablePermission = {
  readonly type: "TablePermission";
  readonly table: Table;
  readonly actions: readonly TableAction[];
};

export type UserPoolAction =
  | "ListUsers"
  | "AdminCreateUser"
  | "AdminGetUser"
  | "AdminLinkProviderForUser"
  | "AdminDeleteUser";
export type UserPoolPermission = {
  readonly type: "UserPoolPermission";
  readonly userPool: UserPool;
  readonly actions: readonly UserPoolAction[];
};

export type SendMailPermission = {
  readonly type: "SendMailPermission";
  readonly identity: Parameter;
};

export type IAMActionPermission = {
  readonly type: "IAMActionPermission";
  readonly actions: readonly string[];
  readonly resources: readonly (string | ResourceOutputReference)[];
};

export type Permission =
  | TablePermission
  | UserPoolPermission
  | SendMailPermission
  | IAMActionPermission;

export const reducePermission = <B>(
  fT: (t: TablePermission) => B,
  fU: (u: UserPoolPermission) => B,
  fS: (s: SendMailPermission) => B,
  fI: (i: IAMActionPermission) => B
) => (p: Permission): B => {
  if (isTablePermission(p)) {
    return fT(p);
  }

  if (isSendMailPermission(p)) {
    return fS(p);
  }

  if (isIAMActionPermission(p)) {
    return fI(p);
  }

  return fU(p);
};

export type LambdaFunction = {
  readonly permissions: readonly Permission[];
  readonly environment: readonly EnvironmentVariable[];
  readonly eventSource?: Table;
};

export const isTablePermission = (t: Permission): t is TablePermission =>
  t.type === "TablePermission";

export const isUserPoolPermission = (t: Permission): t is UserPoolPermission =>
  t.type === "UserPoolPermission";

export const isSendMailPermission = (t: Permission): t is SendMailPermission =>
  t.type === "SendMailPermission";

export const isIAMActionPermission = (
  t: Permission
): t is IAMActionPermission => t.type === "IAMActionPermission";

export const resourceRefForTable = (table: Table): ResourceOutputReference =>
  new ResourceOutputReference("api", table.apiName, "GraphQLAPIIdOutput");

export class TableNameVariable {
  constructor(public readonly table: Table) {}
}

export class ParameterVariable {
  constructor(
    public readonly name: string,
    public readonly parameter: Parameter
  ) {}
}

export class ResourceOutputVariable {
  constructor(
    public readonly name: string,
    public readonly reference: ResourceOutputReference
  ) {}
}

export type VariableValueExpression = Parameter | ResourceOutputReference;

export const reduceVariableValueExpression = <B>(
  fP: (p: Parameter) => B,
  fR: (r: ResourceOutputReference) => B
) => (e: VariableValueExpression): B => {
  if (e instanceof Parameter) {
    return fP(e);
  }

  return fR(e);
};

export class CoalescedVariable {
  constructor(
    public readonly name: string,
    public readonly first: VariableValueExpression,
    public readonly second: VariableValueExpression
  ) {}
}

export type EnvironmentVariable =
  | TableNameVariable
  | ParameterVariable
  | ResourceOutputVariable
  | CoalescedVariable;

export const reduceEnvionmentVariable = <B>(
  fT: (t: TableNameVariable) => B,
  fP: (u: ParameterVariable) => B,
  fR: (s: ResourceOutputVariable) => B,
  fC: (c: CoalescedVariable) => B
) => (v: EnvironmentVariable): B => {
  if (v instanceof TableNameVariable) {
    return fT(v);
  }

  if (v instanceof ParameterVariable) {
    return fP(v);
  }

  if (v instanceof ResourceOutputVariable) {
    return fR(v);
  }

  return fC(v);
};
