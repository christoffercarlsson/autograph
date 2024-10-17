Pod::Spec.new do |s|
  s.name             = 'AutographProtocol'
  s.module_name      = 'Autograph'
  s.version          = '1.0.0-alpha.4'
  s.summary          = 'The Autograph Protocol'
  s.description      = <<-DESC
                        Autograph is an open, modular cryptographic protocol that implements a
                        decentralized credential management system. It is efficient enough to run on
                        virtually any type of device, completely offline.
                        DESC
  s.homepage         = 'https://autograph.sh'
  s.license          = { :type => 'Unlicense', :file => 'LICENSE' }
  s.author           = { 'Christoffer Carlsson' => 'cc@christoffercarlsson.se' }
  s.source           = { :git => 'https://github.com/christoffercarlsson/autograph.git', :tag => s.version }

  s.ios.deployment_target = '13.4'
  s.swift_version    = '5.4'

  s.vendored_frameworks = 'apple/Clibautograph.xcframework'
  s.source_files = 'apple/Sources/Autograph/**/*.{swift,h}'
end
