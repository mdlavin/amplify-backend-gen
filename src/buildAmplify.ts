#!/usr/bin/env node

import { promises as fs } from "fs";
import * as path from "path";
import {
  buildCloudFormationTemplate,
  CFEnvironment,
  CFPermissions,
  TableParameterProvider,
  TableDetailProvider,
  TableResourceOutputReferenceProvider,
} from "./buildCloudFormationTemplate";
import webpack from "webpack";
import { flatten, groupBy, uniqBy } from "lodash";
import { LambdaFunction } from "./types";
import { fork } from "child_process";
import yargs from "yargs";
import { register as registerTsNode } from "ts-node";

registerTsNode();

const isString = (s: string | undefined): s is string => !!s;

const buildFunction = async (
  handlersDir: string,
  handlerDir: string,
  amplifyBackendDir: string
) => {
  if (!(await fs.stat(path.join(handlersDir, handlerDir))).isDirectory())
    return;
  console.log("Looking at", handlerDir);

  const metadataModulePath = path.join(
    process.cwd(),
    handlersDir,
    handlerDir,
    "metadata"
  );
  const metadata = (await import(metadataModulePath)).default as LambdaFunction;
  console.log("Config:", metadata);

  const CFTable = {
    ...TableParameterProvider,
    ...TableDetailProvider,
    ...TableResourceOutputReferenceProvider,
  };

  const cfTemplate = buildCloudFormationTemplate({
    eventSource: metadata.eventSource,
    name: handlerDir,
    environment: metadata.environment,
    permissions: metadata.permissions,
    cfEnvironment: CFEnvironment,
    cfPermissions: CFPermissions,
    cfTable: CFTable,
  });

  const outputDir = path.join(amplifyBackendDir, "function", handlerDir);

  await fs.mkdir(outputDir, { recursive: true });

  await fs.writeFile(
    path.join(outputDir, `${handlerDir}-cloudformation-template.json`),
    JSON.stringify(cfTemplate, null, "\t"),
    "utf8"
  );

  const backendConfigFile = path.join(amplifyBackendDir, "backend-config.json");
  const backendConfig = JSON.parse(
    await fs.readFile(backendConfigFile, "utf8")
  );

  const resourceReferences = groupBy(
    uniqBy(
      [
        ...flatten(metadata.environment.map(CFEnvironment.toOutputReferences)),
        ...flatten(metadata.permissions.map(CFPermissions.toOutputReferences)),
        ...(metadata.eventSource
          ? CFTable.toOutputReferences(metadata.eventSource)
          : []),
      ],
      ({ category, resource, output }) => `${category}-${resource}-${output}`
    ),
    ({ category, resource }) => `${category}-${resource}`
  );

  backendConfig.function[handlerDir] = {
    service: "Lambda",
    providerPlugin: "awscloudformation",
    build: true,
    dependsOn: Object.values(resourceReferences).map((references) => ({
      category: references[0].category,
      resourceName: references[0].resource,
      attributes: references.map(({ output }) => output),
    })),
  };
  await fs.writeFile(
    backendConfigFile,
    JSON.stringify(backendConfig, null, 2),
    "utf8"
  );

  const srcOutputDir = path.join(outputDir, "src");
  await fs.mkdir(srcOutputDir, { recursive: true });

  await fs.writeFile(
    path.join(srcOutputDir, "package.json"),
    JSON.stringify(
      {
        name: handlerDir,
        version: "2.0.0",
        description: "Lambda function generated by Amplify",
        main: "index.js",
        license: "Apache-2.0",
      },
      null,
      2
    ),
    "utf8"
  );

  const webpackConfig: webpack.Configuration = {
    entry: path.join(process.cwd(), handlersDir, handlerDir, "src", "index.ts"),
    output: {
      publicPath: "./",
      path: srcOutputDir,
      filename: "index.js",
      libraryTarget: "commonjs2",
    },
    target: "node",
    node: false,
    mode: "none",
    resolve: {
      extensions: [".ts", ".tsx", ".json", ".js"],
    },
    externals: {
      "aws-sdk": "commonjs2 aws-sdk",
    },
    module: {
      rules: [
        {
          test: /\.tsx?$/,
          use: [{ loader: require.resolve("ts-loader") }],
        },
        {
          test: /\.html?$/,
          use: [
            {
              loader: require.resolve("file-loader"),
            },
          ],
        },
      ],
    },
  };

  const packer = webpack(webpackConfig);

  await new Promise((resolve, reject) =>
    packer.run((err, stats) => {
      if (err) {
        reject(err);
      } else {
        if (stats.hasErrors()) {
          const info = stats.toJson();
          throw new Error(JSON.stringify(info.errors, null, 2));
        }

        resolve();
      }
    })
  );
};

const main = async () => {
  const args = yargs
    .option("functions", {
      alias: "f",
      type: "string",
      nargs: 1,
      required: true,
    })
    .option("build", {
      alias: "b",
      type: "string",
    })
    .option("amplify-backend", {
      alias: "a",
      type: "string",
      default: "amplify/backend",
      required: true,
    }).argv;

  console.log(args);

  const handlersDir = args.functions;

  const selfModule = args.$0;

  const dirToBuild = args.build;
  if (dirToBuild) {
    const amplifyBackendDir = path.join(process.cwd(), args["amplify-backend"]);
    await buildFunction(handlersDir, dirToBuild, amplifyBackendDir);
    return;
  }

  const contents = await fs.readdir(handlersDir);
  const handlerDirs = (
    await Promise.all(
      contents.map(async (name) =>
        (await fs.stat(path.join(handlersDir, name))).isDirectory()
          ? name
          : undefined
      )
    )
  ).filter(isString);

  for (const handlerDir of handlerDirs) {
    // Launch each build in a seperate process because webpack seems
    // to have a memory leak when run multiple times in the same process
    const child = fork(selfModule, [
      "-f",
      args.functions,
      "-b",
      handlerDir,
      "-a",
      args["amplify-backend"],
    ]);
    await new Promise((resolve, reject) => {
      child.on("close", (code) =>
        code ? reject(new Error(`${code}`)) : resolve()
      );
      child.on("error", (error) => reject(error));
    });
  }
};

main().catch((e) => {
  console.error(e);
  process.exitCode = 1;
});
