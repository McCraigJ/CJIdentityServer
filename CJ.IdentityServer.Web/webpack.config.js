const webpack = require('webpack');
const path = require('path');
const ExtractTextPlugin = require('extract-text-webpack-plugin');

const GLOBALS = {
  'process.env.NODE_ENV': JSON.stringify('production')
};
const PROD = process.env.NODE_ENV === 'production';

module.exports = {
  entry: PROD ? './assetincludes-prod.js' : './assetincludes.js',
  output: {
    path: path.join(__dirname + "/wwwroot", 'dist'),
    filename: 'bundle.js'
  },
  devtool: PROD ? 'source-map' : 'source-map',
  resolve: {
    extensions: ['.js', '.jsx'],
    alias: {
      '../../theme.config$': path.join(__dirname, 'src/styles/theme.config')
    }
  },
  plugins: PROD ?
    [
      new webpack.optimize.OccurenceOrderPlugin(),
      new webpack.DefinePlugin(GLOBALS),
      new ExtractTextPlugin('bundle.css'),
      new webpack.optimize.DedupePlugin(),
      new webpack.optimize.UglifyJsPlugin({ compress: { warnings: false } })
    ] :
    [
      new webpack.HotModuleReplacementPlugin(),
      new webpack.NoErrorsPlugin()
    ],
  module: {    
    rules: [
      // this handles .less translation
      {
        use: ExtractTextPlugin.extract({
          use: ['css-loader?sourceMap', 'less-loader?sourceMap']
        }),
        test: /\.less$/
      },
      {
        test: /\.jpe?g$|\.gif$|\.png$|\.ttf$|\.eot$|\.svg$/,
        use: 'file-loader?name=[name].[ext]?[hash]'
      },
      {
        test: /\.woff(2)?(\?v=[0-9]\.[0-9]\.[0-9])?$/,
        loader: 'url-loader?limit=10000&mimetype=application/fontwoff'
      }
    ]
  },
  plugins: [
    // this handles the bundled .css output file
    new ExtractTextPlugin({
      filename: '[name].css'
    })
  ]
};
