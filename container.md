```yml
FROM scratch
# is the best Go docker image
```

```sh

That's a dangerous piece of advice.If your app does not need to send https requests, never creates temporary files or converts dates from one time zone to another, you mignt be indeed good with a scratch image.But the moment the app tries to do one of the above, it will panic


FROM scratch container images miss;
- System folders like /tmp or /home
- Proper user management
-CA certificates
- Timezone database
- ?

```
```sbt

import com.typesafe.sbt.packager.docker._
dockerCommands := Seq(
  //Cmd("FROM", "openjdk:12.0.1-jdk-oracle"),
  Cmd("FROM", "openjdk:20-slim"),
  //Cmd("FROM", "openjdk:8-jre-slim"),
  Cmd("LABEL", s"""MAINTAINER="${(maintainer in Docker).value}""""),
  Cmd("ADD", s"lib/${(assembly in mainRunner).value.getName}", "/opt/tsp.jar"),
  ExecCmd("CMD", "sh", "-c", "java ${TSP_JAVA_OPTS:--Xms1G -Xmx6G} -jar /opt/tsp.jar")
)
Docker/dockerEntrypoint
Docker/dockerEntrypoint := Seq("/opt/docker/bin/bootstrap-play2", "-Dplay.server.pidfile.path=/dev/null")

```

```sbt


  Test / testOptions := Seq(Tests.Argument("-oDF"))

  IntegrationTest / testOptions := Seq(Tests.Argument("-oDF"))

  IntegrationTest / unmanagedResourceDirectories += (baseDirectory.value / ".." / ".." / "frontends" / "benchmarks")
  Compile / unmanagedSourceDirectories           += (baseDirectory.value / ".." / ".." / "frontends" / "common" / "src" / "main" / "scala")
  Test / unmanagedSourceDirectories              += (baseDirectory.value / ".." / ".." / "frontends" / "common" / "src" / "test" / "scala")
  IntegrationTest / unmanagedSourceDirectories   += (baseDirectory.value / ".." / ".." / "frontends" / "common" / "src" / "it" / "scala")

  //IntegrationTest / testGrouping := Testing.makeTestGroups(integrationTestsWithFixtures.value)
  IntegrationTest / testOptions += Tests.Argument("-oF")  // show full stack traces

  reStart / mainClass := Some("uniso.app.AppServer")


Test / testOptions += Tests.Argument(TestFrameworks.ScalaTest, "-o", "-h", "report")

//IntegrationTest / testOptions += Tests.Argument(TestFrameworks.ScalaTest, "-h", "it-report")

Compile / unmanagedResourceDirectories += (LocalRootProject / baseDirectory).value / "swagger-ui"

  ```

  ```sbt
  //.sbtopts
-J-Xmx3G
-J-Xms1G
-J--add-opens=java.base/java.util=ALL-UNNAMED
-J--add-opens=java.base/java.lang=ALL-UNNAMED
  ```

`unmanagedBase`->`lib/`  

`unmanagedResourceDirectories`->`src/main/resources`

```scala
 //Classpath: Resources under src/main/resources are automatically added to the classpath by SBT during both compilation and packaging.
  //The path to the resource you want to load. The path should start with a / if it’s an absolute path, relative to the classpath root.
  val rawtransactions=Source.fromInputStream(getClass.getResourceAsStream("/transactions.txt"))
```

```sbt
// Scoped to a specific task (run) in the compile configuration
Compile / run / javaOptions += "-Dconfig.resource=application.conf"

```
3 main scopes in sbt,
- project
- configuration 
- task

In sbt, there are three axes that determine scope:

- Zero: The default/global scope.
- One: Can represent a single dimension (e.g., a specific configuration like Test or a specific task like compile).
- Two or more: More refined scopes that might involve both a configuration and a task (e.g., Compile / run / fork).


`Project / Configuration / Task / settingKey := value`

Compose tasks by using the .dependsOn method or by calling one task from within another.

## Task Dependencies

```sbt
lazy val myTask = taskKey[Unit]("A custom task that depends on compile")

myTask := {
  val _ = compile.value  // This ensures that `compile` runs before `myTask`
  println("Compilation completed. Now executing myTask.")
}

```
## Task Chaining
```sbt

lazy val taskA = taskKey[Unit]("Task A")
lazy val taskB = taskKey[Unit]("Task B, depends on task A")

taskA := {
  println("Running task A")
}

taskB := Def.sequential(taskA, Def.task {
  println("Running task B after task A")
})
//taskB depends on taskA and runs after taskA is completed
```

Tasks represent actions that can be executed, while settings define values or configurations that can influence the behavior of tasks

Tasks produce values and are referenced by a key.Tasks can produce any scala type
 Tasks can have other tasks or attributes as input. To see it in action,let's write a task that takes the value of another task and multiplies it
 
 ```sbt
lazy val one= taskKey[Int]("One")

one:= 1

lazy val oneTimesTwo=taskKey[Unit]("One times two")

oneTimesTwo:= println(s"2*1=${one.value*2}")

 ```

 [study-sbt](https://github.com/dnvriend/study-sbt)
## Build & Project
 A Build concerns itself with one or more projects, and a projects concerns itself with settings.

 ## Settings
 So a Build builds projects, Projects define themselves using settings;a Setting is a Key -> Value pair

 ## Tasks
So a Build builds projects, Projects define themselves using settings, and settings are Key -> Value pairs that are initialized only once when Sbt launches. A Task is a Key -> Value pair that is evaluated on demand. A Task exists to be evaluated every time it is needed.

- Setting can depend on another setting

- A setting can't depend on a Task

- A Task can depend on both a setting and other Tasks

## Configurations
Sbt uses Configurations to segment Settings so it knows which setting to use when a certain task is being executed

```sbt
// first define a task key
lazy val mytest = taskKey[Unit]("My test key to show how scoped settings work")

// then implement the task key
mytest := {
	val dirs = (sourceDirectories in Test).value
	println(dirs)
}

lazy val mycompile = taskKey[Unit]("My compile key to show how scoped settings work")

mycompile := {
	val dirs = (sourceDirectories in Compile).value
	println(dirs)
}

```
`sourceDirectories` has a different value for different scopes 

## Configuration by Task
A configuration can also be scoped to a specific Task 

```sbt

lazy val mysetting = settingKey[String]("My setting")

mysetting := "mysetting for the current project, all configurations and all tasks"

mysetting in Test := "mysetting for the current project, for the Test configuration and all tasks"

mysetting in Test in myTask := "mysetting for the current project, for the Test configuration for the task MyTask only"

lazy val myTask = taskKey[Unit]("My task")

myTask := {
    val str = (mysetting in Test in myTask).value
    println(str)
}

```
The setting applies only when myTask is invoked within the Test configuration
Setting--> like val
Task --> like def

A scope is a tuple of components in three axes: (the subproject axis, the configuration axis, and the task axis).

## Returning a task based on a setting
A task can return a different task based on a value of a setting:

```sbt
lazy val choice = settingKey[String]("The task to execute")
choice := "t1"

lazy val staticChoice = taskKey[Unit]("")
staticChoice := Def.taskDyn {
  choice.value match {
    case "t1" => task1.toTask
    case "t2" => task2.toTask
    case "t3" => task3.toTask
    case "all" => runAll.toTask
    case _ => runAllSequential.toTask
  }
}.value

```
Keys can easily be configured so that they have a value in a specific Configuration, Task or (Configuration,Task) combination.

`(project/config:task::setting)`

`ThisBuild`: All projects and all configuration and all tasks in the current build only.

`Settings` parameterize the build, they are evaluated once when sbt loads the project

`Tasks` perform actions(download,compile,run etc), they are evaluated at each invocation

`Tasks` can be parameterized by `Settings` values and other `Tasks` results

A key can have different values in different scopes

Configurations are one possible axis of key scoping

Keys can have different values according to a particular task
for instance, the task `unmanagedSources` list all the project source files

The task can be configured by changing the value of the setting `includeFilter`

in the scope of the task `unmanagedSources`
unmanagedSources/includeFilter


Here is how we can see the value of the `includeFilter`  key according to multiple axes:

//current project, no configuration, unmanagedSources task
- unmanagedSources/includeFilter

//hello-sbt project, no configuration, unmanagedSources task
- hello-sbt/unmanagedSources/includeFilter

//hello-sbt project, Compile configuration, unmanagedSources task
- hello-sbt/Compile unmanagedSources/includeFilter

When you scope `includeFilter` to `unmanagedSources`, it means that the filter will only affect the behavior of the unmanagedSources task. In other words, it determines which files should be included when sbt is collecting the unmanaged source files.
By scoping `includeFilter` to `unmanagedSources`, you limit its effect to just this specific task.

`includeFilter` is a `Setting` scoped to `unmanagedSources` Task
Scoping settings to tasks allows you to apply specific settings only when that task is executed.

Each key can have an associated value in more than one context, called a "scope"

Settings can affect how a task works. For example the `packageSrc` task is affected by the `packageOptions` setting..  That is why a task key like `packageSrc` can be a scope for another, such as `packageOptions`

`packageSrc`,`packageBin`,`packageDoc` all depend on `packageOptions`. We can have different values for `packageOptions` for any of these 3 tasks. This is done by using the task axis



  `packageDoc/packageOptions`
  packageDoc--> Task
  packageOptions --> Task
  A task can be scoped another task



  By default,
  - project axis is set to current project
  - configuration axis to `Global`
  - task axis to `Global`

A dependency configuration (or “configuration” for short) defines a graph of library dependencies, potentially with its own classpath, sources, generated packages, etc

Some configurations you’ll see in sbt:

- Compile which defines the main build (src/main/scala).
- Test which defines how to build tests (src/test/scala).
- Runtime which defines the classpath for the run task.
By default, all the keys associated with compiling, packaging, and running are scoped to a configuration and therefore may work differently in each configuration. The most obvious examples are the task keys compile, package, and run; but all the keys which affect those keys (such as sourceDirectories or scalacOptions or fullClasspath) are also scoped to the configuration.

Test and IntegrationTest extends Runtime; Runtime extends Compile; CompileInternal extends Compile, Optional, and Provided.

Settings can affect how a task works. For example, the `packageSrc` task is affected by the `packageOptions` setting

## Zero scope component 
Each scope axis can be filled in with an instance of the axis type (analogous to `Some(_)`), or the axis can be filled in with the special value `Zero`. So we can think of `Zero` as `None`.

`Zero` is a universal fallback for all scope axes, but its direct use should be reserved to sbt and plugin authors in most cases.

`Global` is a scope that sets `Zero` to all axes: `Zero / Zero / Zero`. In other words, `Global / someKey` is a shorthand for `Zero / Zero / Zero / someKey`.

### Referring to scopes in a build definition 
If you create a setting in build.sbt with a bare key, it will be scoped to `(current subproject / configuration Zero / task Zero)`:

```sbt
// same as Zero / Zero / Zero / concurrentRestrictions
Global / concurrentRestrictions := Seq(
  Tags.limitAll(1)
)
```

`(Global / concurrentRestrictions` implicitly converts to `Zero / Zero / Zero / concurrentRestrictions`, setting all axes to `Zero` scope component; the task and configuration are already `Zero` by default, so here the effect is to make the project `Zero`, that is, define `Zero / Zero / Zero / concurrentRestrictions` rather than `ProjectRef(uri("file:/tmp/hello/"), "root") / Zero / Zero / concurrentRestrictions)`

`ref / Config / intask / key`

`ref` identifies the subproject axis. It could be `<project-id>`, `ProjectRef(uri("file:..."), "id")`, or `ThisBuild` that denotes the “entire build” scope.
- `Config` identifies the configuration axis using the capitalized Scala identifier.
- `intask` identifies the task axis.
- `key` identifies the key being scoped.

`Zero` can appear for each axis.

A file system is a structure used by an operating system to organise and manage files on a storage device such as a hard drive, solid state drive (SSD), or USB flash drive. It defines how data is stored, accessed, and organised on the storage device. Different file systems have varying characteristics and are often specific to certain operating systems or devices.

- When you build a Docker image, each instruction in the Dockerfile (e.g., COPY, RUN, ADD) creates a new layer.

- Each layer is built on top of the previous one, and Docker saves these layers on disk, utilizing the host machine’s file system
- Docker uses a union file system (e.g., OverlayFS) to efficiently merge the layers into a single file system view.

```yml
FROM ubuntu:latest
RUN apt-get update && apt-get install -y nginx
COPY . /app

```
  
- The base layer (ubuntu:latest) is reused if already present.
- The RUN command creates a new layer where Nginx is installed.
- The COPY command creates another layer where the /app directory is added.

Image Layers:

- Layer 1: /bin directory with core system binaries.
- Layer 2: /usr directory with additional packages installed.
- Layer 3: /app directory containing your application code.

These layers are combined into a single file system by Docker using OverlayFS. The container sees

```sh
/
├── bin/        (from Layer 1)
├── usr/        (from Layer 2)
└── app/        (from Layer 3)
```
The container sees all the layers as a single unified file system, even though the data is stored in separate layers on disk

```sh
# Stage 1: Build the application
FROM golang:1.18 AS builder
WORKDIR /app
COPY . .
RUN go build -o myapp .

# Stage 2: Create a minimal runtime image
FROM alpine
WORKDIR /app
COPY --from=builder /app/myapp .
CMD ["./myapp"]

```

In this example, the Go build tools and dependencies are excluded from the final image, which only contains the compiled application

- Each command in a Dockerfile creates a new layer, so try to combine commands to reduce the number of layers. This can reduce the overall image size by eliminating unnecessary intermediate layers.

- Clean Up After Installing Dependencies


Filesystems describe our data. With filesystems, we have folders, access control, and named files. Without them, our disk would be just a soup of bits. We wouldn’t know where anything was stored, where things start or end, or any external information (metadata).

A file system defines how files are named, stored, and retrieved from a storage device.

Docker Image
Each Docker image references a list of read-only layers that represent filesystem differences. Layers are stacked on top of each other to form a base for a container’s root filesystem. The Docker storage driver is responsible for stacking these layers and providing a single unified view.

[docker-containers-filesystem-demystified](https://medium.com/@BeNitinAgarwal/docker-containers-filesystem-demystified-b6ed8112a04a)

`LowerDir`: Includes the filesystems of all the layers inside the container except the last one
`UpperDir`: The filesystem of the top-most layer of the container. This is also where any run-time modifications are reflected.
`MergedDir`: A combined view of all the layers of the filesystem.
`WorkDir`: An internal working directory used to manage the filesystem.

![alt text](image-111.png)

So to see the files inside our container, we simply need to look at the MergedDir path

`sudo ls /var/lib/docker/overlay2/63ec1a08b063c0226141a9071b5df7958880aae6be5dc9870a279a13ff7134ab/merged`

[Deep Dive into Docker Internals - Union Filesystem
](https://martinheinz.dev/blog/44)