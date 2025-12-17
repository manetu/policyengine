// Docusaurus plugin to configure dev server proxy for iubenda API
module.exports = function () {
  return {
    name: 'iubenda-proxy',
    configureWebpack() {
      return {
        devServer: {
          proxy: [
            {
              context: ['/api/iubenda'],
              target: 'https://www.iubenda.com',
              changeOrigin: true,
              pathRewrite: {'^/api/iubenda': '/api'},
            },
          ],
        },
      };
    },
  };
};
