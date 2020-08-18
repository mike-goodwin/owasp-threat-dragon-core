// var cover = require('browserify-istanbul');

// var coverOptions = {
//   ignore: ['test/**/*.js'],
//   defaultIgnore: true
// }

module.exports = function (config) {
  config.set({

    // base path that will be used to resolve all patterns (eg. files, exclude)
    basePath: '',

    // frameworks to use
    // available frameworks: https://npmjs.org/browse/keyword/karma-adapter
    frameworks: ['phantomjs-shim', 'jasmine', 'browserify'],

    // list of files / patterns to load in the browser
    files: [
      { pattern: 'node_modules/babel-polyfill/browser.js', instrument: false},
      'test/spec/*.js'
    ],

    // list of files to exclude
    exclude: [],

    // preprocess matching files before serving them to the browser
    // available preprocessors: https://npmjs.org/browse/keyword/karma-preprocessor
    preprocessors: {
      'test/**/*.js': ['browserify']
    },

    browserify: {
      transform: [
        require("browserify-istanbul")
      ],
      debug: true
    },

    // test results reporter to use
    // available reporters: https://npmjs.org/browse/keyword/karma-reporter
    reporters: ['spec', 'coverage', 'threshold'],

    //config for coverage reporter
    coverageReporter: {
      reporters: [{ type: 'lcov' }]
    },

    //config for threashhold reporter
    thresholdReporter: {
      statements: 90,
      branches: 75,
      functions: 90,
      lines: 90
    },

    // web server port
    port: 9876,

    // enable / disable colors in the output (reporters and logs)
    colors: true,

    // level of logging
    // possible values: config.LOG_DISABLE || config.LOG_ERROR || config.LOG_WARN || config.LOG_INFO || config.LOG_DEBUG
    logLevel: config.LOG_INFO,

    // enable / disable watching file and executing tests whenever any file changes
    autoWatch: true,

    // start these browsers
    // available browser launchers: https://npmjs.org/browse/keyword/karma-launcher
    browsers: ['Chrome', 'Firefox', 'IE', 'PhantomJS'],

    // Continuous Integration mode
    // if true, Karma captures browsers, runs the tests and exits
    singleRun: false,

    // Concurrency level
    // how many browser should be started simultaneous
    concurrency: Infinity
  })
}
