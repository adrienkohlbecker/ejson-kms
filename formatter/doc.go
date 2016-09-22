// Package formatter is a collection of functions used to format secrets for
// output. Currently formatters for Bash, JSON and Dotenv are implemented.
//
// Example
//
// Here is how to use the formatters:
//
//   items := make(chan formatter.Items, 1)
//   items <- formatter.Item{Name: "secret", Plaintext: "password"}
//
//   switch format {
//     case "bash":
//       // export SECRET="password"
//       formatter.Bash(os.Stdout, items)
//     case "dotenv":
//       // SECRET="password"
//       formatter.Dotenv(os.Stdout, items)
//     case "json":
//       // { "secret": "password" }
//       formatter.JSON(os.Stdout, items)
//  }
package formatter
