const gulp = require('gulp');
const runSequence = require('run-sequence').use(gulp);
const del = require('del');

gulp.task('clean', () => {
  return del(['wwwroot/dev/**/*']);
});

var less = require('gulp-less');
var path = require('path');

gulp.task('less', function () {
  return gulp.src('./wwwroot/**/*.less')
    .pipe(less({
      paths: [path.join(__dirname, 'less', 'includes')]
    }))
    .pipe(gulp.dest('./wwwroot/dev/css'));
});

// Default task, bundles the entire app and hosts it on an Express server
gulp.task('default', (cb) => {
  runSequence('clean', 'less', cb);
});
