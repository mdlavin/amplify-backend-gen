import { uniq, fromPairs, merge, flatten } from "lodash";
import {
  reduceVariableValueExpression,
  TableAction,
  Permission,
  UserPoolAction,
  EnvironmentVariable,
  ResourceOutputReference,
  userPoolOutputReference,
  TableNameVariable,
  apiTableOutputReference,
  ParameterVariable,
  ResourceOutputVariable,
  Parameter,
  Table,
  CoalescedVariable,
  reducePermission,
  reduceEnvionmentVariable,
} from "./types";

export type CFParameter = {
  type: "Parameter";
  name: string;
  defaultValue?: string;
};

export interface ParameterProvider<T> {
  toParameter(t: T): CFParameter;
}

export interface ParametersProvider<T> {
  toParameters(t: T): Parameter[];
}

export const SingleParameterParametersProvider = {
  toParameters<T>(P: ParameterProvider<T>, t: T) {
    return [P.toParameter(t)];
  },
};

type CFConditionDefinition = {
  name: string;
  block: object;
};

type CFVariableDefinition = {
  name: string;
  block: object | string;
};

export interface VariableProvider<T> {
  toVariable(t: T): CFVariableDefinition;
}

export interface ExpressionProvider<T> {
  toExpression(t: T): string | object;
}

export interface ResourceOutputReferenceProvider<T> {
  toOutputReferences(t: T): ResourceOutputReference[];
}

export interface ConditionProvider<T> {
  toConditions(t: T): CFConditionDefinition[];
}

export interface TableDetailProvider<T> {
  toArnExpression(t: T): object | string;
  toNameExpression(t: T): object | string;
  toStreamArnExpression(t: T): object | string;
}

export interface PolicyProvider<T> {
  toPolicyStatement(t: T): object;
}

const ResourceOutputReferenceParameterProvider: ParameterProvider<ResourceOutputReference> = {
  toParameter(ref: ResourceOutputReference) {
    const name = `${ref.category}${ref.resource}${ref.output}`;
    return {
      type: "Parameter",
      name,
    } as const;
  },
};

const ParameterExpressionProvider: ExpressionProvider<Parameter> = {
  toExpression: (p: Parameter) => ({
    Ref: p.name,
  }),
};

const ResourceOutputReferenceExpressionProvider: ExpressionProvider<ResourceOutputReference> = {
  toExpression(ref: ResourceOutputReference) {
    return ParameterExpressionProvider.toExpression(
      ResourceOutputReferenceParameterProvider.toParameter(ref)
    );
  },
};

export const TableParameterProvider: ParameterProvider<Table> = {
  toParameter(table) {
    return ResourceOutputReferenceParameterProvider.toParameter(
      apiTableOutputReference(table)
    );
  },
};

export const TableResourceOutputReferenceProvider: ResourceOutputReferenceProvider<Table> = {
  toOutputReferences: (table) => [apiTableOutputReference(table)],
};

export const TableDetailProvider: TableDetailProvider<Table> = {
  toNameExpression(table) {
    const tableParameter = TableParameterProvider.toParameter(table);
    return {
      "Fn::ImportValue": {
        "Fn::Sub": `\${${tableParameter.name}}:GetAtt:${table.tableName}Table:Name`,
      },
    };
  },
  toArnExpression(table) {
    const tableParameter = TableParameterProvider.toParameter(table);
    return {
      "Fn::ImportValue": {
        "Fn::Sub": `\${${tableParameter.name}}:GetAtt:${table.tableName}Table:Arn`,
      },
    };
  },
  toStreamArnExpression(table) {
    const tableParameter = TableParameterProvider.toParameter(table);
    return {
      "Fn::ImportValue": {
        "Fn::Sub": `\${${tableParameter.name}}:GetAtt:${table.tableName}Table:StreamArn`,
      },
    };
  },
};

const policyActionForTableAction = (action: TableAction) => {
  switch (action) {
    case "ReadItem":
      return "dynamodb:GetItem";
    case "UpdateItem":
      return "dynamodb:UpdateItem";
  }
};

const policyActionForUserPoolAction = (action: UserPoolAction) => {
  switch (action) {
    case "AdminDeleteUser":
    case "AdminGetUser":
    case "AdminCreateUser":
    case "AdminLinkProviderForUser":
    case "ListUsers":
      return `cognito-idp:${action}`;
  }
};

const PermissionPolicyProvider: PolicyProvider<Permission> = {
  toPolicyStatement: reducePermission<object>(
    (permission) => {
      const table = permission.table;
      const tableParam = ResourceOutputReferenceParameterProvider.toParameter(
        apiTableOutputReference(table)
      );
      return {
        Effect: "Allow",
        Action: permission.actions.map(policyActionForTableAction),
        Resource: [
          {
            "Fn::Sub": [
              "arn:aws:dynamodb:${region}:${account}:table/${tableName}",
              {
                region: {
                  Ref: "AWS::Region",
                },
                account: {
                  Ref: "AWS::AccountId",
                },
                tableName: {
                  "Fn::ImportValue": {
                    "Fn::Sub": `\${${tableParam.name}}:GetAtt:${table.tableName}Table:Name`,
                  },
                },
              },
            ],
          },
        ],
      };
    },
    (permission) => {
      const userPoolIdExpression = ResourceOutputReferenceExpressionProvider.toExpression(
        userPoolOutputReference(permission.userPool, "UserPoolId")
      );

      return {
        Effect: "Allow",
        Action: permission.actions.map(policyActionForUserPoolAction),
        Resource: {
          "Fn::Sub": [
            "arn:aws:cognito-idp:${region}:${account}:userpool/${userPoolId}",
            {
              region: {
                Ref: "AWS::Region",
              },
              account: {
                Ref: "AWS::AccountId",
              },
              userPoolId: userPoolIdExpression,
            },
          ],
        },
      };
    },
    (permission) => {
      return {
        Effect: "Allow",
        Action: ["ses:SendEmail"],
        Resource: {
          "Fn::Sub": `\${${permission.identity.name}}`,
        },
      };
    },
    (permission) => {
      return {
        Effect: "Allow",
        Action: permission.actions,
        Resource: permission.resources.map((resource) =>
          typeof resource === "string"
            ? resource
            : ResourceOutputReferenceExpressionProvider.toExpression(resource)
        ),
      };
    }
  ),
};

const PermissionParametersProvider: ParametersProvider<Permission> = {
  toParameters: reducePermission(
    ({ table }) => [
      ResourceOutputReferenceParameterProvider.toParameter(
        apiTableOutputReference(table)
      ),
    ],
    ({ userPool }) => [
      ResourceOutputReferenceParameterProvider.toParameter(
        userPoolOutputReference(userPool, "UserPoolId")
      ),
    ],
    ({ identity }) => valueToParameter(identity),
    ({ resources }) =>
      resources
        .filter(isResourceOutputReference)
        .map(ResourceOutputReferenceParameterProvider.toParameter)
  ),
};

const isResourceOutputReference = (
  resource: string | ResourceOutputReference
): resource is ResourceOutputReference => typeof resource !== "string";

const PermissionResourceOutputReferenceProvider: ResourceOutputReferenceProvider<Permission> = {
  toOutputReferences: reducePermission(
    ({ table }) => [apiTableOutputReference(table)],
    ({ userPool }) => [userPoolOutputReference(userPool, "UserPoolId")],
    () => [],
    ({ resources }) => resources.filter(isResourceOutputReference)
  ),
};

const PermissionConditionProvider: ConditionProvider<Permission> = {
  toConditions() {
    return [];
  },
};

const valueToParameter = (
  value: ResourceOutputReference | Parameter
): CFParameter[] => {
  if (value instanceof ResourceOutputReference) {
    return [ResourceOutputReferenceParameterProvider.toParameter(value)];
  }

  return [
    {
      type: "Parameter",
      name: value.name,
      defaultValue: value.defaultValue,
    },
  ];
};

const EnvironmentVariableParametersProvider: ParametersProvider<EnvironmentVariable> = {
  toParameters(env) {
    if (env instanceof TableNameVariable) {
      return [
        ResourceOutputReferenceParameterProvider.toParameter(
          apiTableOutputReference(env.table)
        ),
      ];
    }

    if (env instanceof ParameterVariable) {
      return valueToParameter(env.parameter);
    }

    if (env instanceof ResourceOutputVariable) {
      return [
        ResourceOutputReferenceParameterProvider.toParameter(env.reference),
      ];
    }

    return [...valueToParameter(env.first), ...valueToParameter(env.second)];
  },
};

const variableValueExpressionToCfExpression = reduceVariableValueExpression(
  ParameterExpressionProvider.toExpression,
  (resource) => ({
    Ref: ResourceOutputReferenceParameterProvider.toParameter(resource).name,
  })
);

const conditionNameForEnv = (env: CoalescedVariable) =>
  `FirstNotEmpty_${env.name}`;

const EnvironmentVariableVariableProvider: VariableProvider<EnvironmentVariable> = {
  toVariable: reduceEnvionmentVariable<CFVariableDefinition>(
    ({ table }) => {
      const tableOutputRef = apiTableOutputReference(table);
      const tableParameter = ResourceOutputReferenceParameterProvider.toParameter(
        tableOutputRef
      );
      return {
        name: `${table.tableName}_table_name`.toUpperCase(),
        block: {
          "Fn::ImportValue": {
            "Fn::Sub": `\${${tableParameter.name}}:GetAtt:${table.tableName}Table:Name`,
          },
        },
      };
    },
    ({ parameter, name }) => ({
      name,
      block: ParameterExpressionProvider.toExpression(parameter),
    }),

    ({ name, reference }) => ({
      name,
      block: ResourceOutputReferenceExpressionProvider.toExpression(reference),
    }),

    (coalescedVar) => ({
      name: coalescedVar.name,
      block: {
        "Fn::If": [
          conditionNameForEnv(coalescedVar),
          variableValueExpressionToCfExpression(coalescedVar.first),
          variableValueExpressionToCfExpression(coalescedVar.second),
        ],
      },
    })
  ),
};

const variableValueExpressionToResourceOutputReferences = reduceVariableValueExpression(
  () => [],
  (reference) => [reference]
);

const EnvironmentVariableResourceOutputReferenceProvider: ResourceOutputReferenceProvider<EnvironmentVariable> = {
  toOutputReferences: reduceEnvionmentVariable<ResourceOutputReference[]>(
    ({ table }) => [apiTableOutputReference(table)],
    () => [],
    ({ reference }) => [reference],
    ({ first, second }) => [
      ...variableValueExpressionToResourceOutputReferences(first),
      ...variableValueExpressionToResourceOutputReferences(second),
    ]
  ),
};

const EnvironmentVariableConditionProvider: ConditionProvider<EnvironmentVariable> = {
  toConditions: reduceEnvionmentVariable(
    () => [],
    () => [],
    () => [],
    (c) => [
      {
        name: conditionNameForEnv(c),
        block: {
          "Fn::Not": [
            {
              "Fn::Equals": [
                variableValueExpressionToCfExpression(c.first),
                "",
              ],
            },
          ],
        },
      },
    ]
  ),
};

export const CFEnvironment: ParametersProvider<EnvironmentVariable> &
  VariableProvider<EnvironmentVariable> &
  ConditionProvider<EnvironmentVariable> &
  ResourceOutputReferenceProvider<EnvironmentVariable> = {
  ...EnvironmentVariableParametersProvider,
  ...EnvironmentVariableVariableProvider,
  ...EnvironmentVariableConditionProvider,
  ...EnvironmentVariableResourceOutputReferenceProvider,
};

export const CFPermissions: ParametersProvider<Permission> &
  PolicyProvider<Permission> &
  ConditionProvider<Permission> &
  ResourceOutputReferenceProvider<Permission> = {
  ...PermissionParametersProvider,
  ...PermissionPolicyProvider,
  ...PermissionConditionProvider,
  ...PermissionResourceOutputReferenceProvider,
};

export const buildCloudFormationTemplate = <T, E, P>({
  name,
  eventSource,
  environment,
  permissions,
  cfEnvironment,
  cfPermissions,
  cfTable,
}: {
  name: string;
  eventSource: T;
  environment: readonly E[];
  permissions: readonly P[];
  cfEnvironment: ParametersProvider<E> &
    VariableProvider<E> &
    ConditionProvider<E>;
  cfPermissions: ParametersProvider<P> &
    PolicyProvider<P> &
    ConditionProvider<P>;
  cfTable: ParameterProvider<T> & TableDetailProvider<T>;
}) => {
  const sourceTableParameter = eventSource
    ? cfTable.toParameter(eventSource)
    : undefined;
  const parameters = uniq(
    flatten([
      ...environment.map(cfEnvironment.toParameters),
      ...permissions.map(cfPermissions.toParameters),
      sourceTableParameter ? [sourceTableParameter] : [],
    ])
  );

  const conditions = flatten([
    ...environment.map(cfEnvironment.toConditions),
    ...permissions.map(cfPermissions.toConditions),
  ]);

  return {
    AWSTemplateFormatVersion: "2010-09-09",
    Description: "Lambda resource stack creation using Amplify CLI",
    Parameters: merge(
      {
        env: {
          Type: "String",
        },
        resourceName: {
          Type: "String",
          Default: name,
        },
      },
      ...parameters.map((parameter) => ({
        [parameter.name]: {
          Type: "String",
          Default: parameter.defaultValue,
        },
      }))
    ),
    Conditions: {
      ShouldNotCreateEnvResources: {
        "Fn::Equals": [
          {
            Ref: "env",
          },
          "NONE",
        ],
      },
      ...fromPairs(
        conditions.map((condition) => [condition.name, condition.block])
      ),
    },
    Resources: {
      LambdaFunction: {
        Type: "AWS::Lambda::Function",
        Metadata: {
          "aws:asset:path": "./src",
          "aws:asset:property": "Code",
        },
        Properties: {
          Handler: "index.handler",
          FunctionName: {
            "Fn::If": [
              "ShouldNotCreateEnvResources",
              name,
              {
                "Fn::Join": [
                  "",
                  [
                    name,
                    "-",
                    {
                      Ref: "env",
                    },
                  ],
                ],
              },
            ],
          },
          Environment: {
            Variables: merge(
              {
                ENV: {
                  Ref: "env",
                },
                REGION: {
                  Ref: "AWS::Region",
                },
              },
              ...environment
                .map(cfEnvironment.toVariable)
                .map(({ name, block }) => ({ [name]: block }))
            ),
          },
          Role: {
            "Fn::GetAtt": ["LambdaExecutionRole", "Arn"],
          },
          Runtime: "nodejs10.x",
          Timeout: "25",
        },
      },
      LambdaExecutionRole: {
        Type: "AWS::IAM::Role",
        Properties: {
          RoleName: {
            "Fn::If": [
              "ShouldNotCreateEnvResources",
              `${name}LambdaRole`,
              {
                "Fn::Join": [
                  "",
                  [
                    `${name}LambdaRole`,
                    "-",
                    {
                      Ref: "env",
                    },
                  ],
                ],
              },
            ],
          },
          AssumeRolePolicyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Principal: {
                  Service: ["lambda.amazonaws.com"],
                },
                Action: ["sts:AssumeRole"],
              },
            ],
          },
        },
      },
      lambdaexecutionpolicy: {
        DependsOn: ["LambdaExecutionRole"],
        Type: "AWS::IAM::Policy",
        Properties: {
          PolicyName: "lambda-execution-policy",
          Roles: [
            {
              Ref: "LambdaExecutionRole",
            },
          ],
          PolicyDocument: {
            Version: "2012-10-17",
            Statement: [
              {
                Effect: "Allow",
                Action: [
                  "logs:CreateLogGroup",
                  "logs:CreateLogStream",
                  "logs:PutLogEvents",
                ],
                Resource: {
                  "Fn::Sub": [
                    "arn:aws:logs:${region}:${account}:log-group:/aws/lambda/${lambda}:log-stream:*",
                    {
                      region: {
                        Ref: "AWS::Region",
                      },
                      account: {
                        Ref: "AWS::AccountId",
                      },
                      lambda: {
                        Ref: "LambdaFunction",
                      },
                    },
                  ],
                },
              },
              ...permissions.map(cfPermissions.toPolicyStatement),
            ],
          },
        },
      },
      ...(eventSource
        ? {
            LambdaTriggerPolicy: {
              DependsOn: ["LambdaExecutionRole"],
              Type: "AWS::IAM::Policy",
              Properties: {
                PolicyName: "amplify-lambda-execution-policy",
                Roles: [
                  {
                    Ref: "LambdaExecutionRole",
                  },
                ],
                PolicyDocument: {
                  Version: "2012-10-17",
                  Statement: [
                    {
                      Effect: "Allow",
                      Action: [
                        "dynamodb:DescribeStream",
                        "dynamodb:GetRecords",
                        "dynamodb:GetShardIterator",
                        "dynamodb:ListStreams",
                      ],
                      Resource: cfTable.toStreamArnExpression(eventSource),
                    },
                  ],
                },
              },
            },
            LambdaEventSourceMapping: {
              Type: "AWS::Lambda::EventSourceMapping",
              DependsOn: ["LambdaTriggerPolicy", "LambdaExecutionRole"],
              Properties: {
                BatchSize: 1,
                MaximumBatchingWindowInSeconds: 1,
                Enabled: true,
                EventSourceArn: cfTable.toStreamArnExpression(eventSource),
                FunctionName: {
                  "Fn::GetAtt": ["LambdaFunction", "Arn"],
                },
                StartingPosition: "LATEST",
              },
            },
          }
        : {}),
    },
    Outputs: {
      Name: {
        Value: {
          Ref: "LambdaFunction",
        },
      },
      Arn: {
        Value: {
          "Fn::GetAtt": ["LambdaFunction", "Arn"],
        },
      },
      Region: {
        Value: {
          Ref: "AWS::Region",
        },
      },
      LambdaExecutionRole: {
        Value: {
          Ref: "LambdaExecutionRole",
        },
      },
    },
  };
};
